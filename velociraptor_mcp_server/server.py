"""
Main MCP server implementation.
"""

import asyncio
import hmac
import json
import logging
from typing import Dict, Optional, Tuple

import uvicorn
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .client import VelociraptorClient
from .config import Config

logger = logging.getLogger(__name__)


# Pydantic models for tool parameters
class AuthenticateArgs(BaseModel):
    """Arguments for authentication tool (no parameters needed)."""

    pass


class GetAgentInfoArgs(BaseModel):
    """Arguments for getting agent information by hostname/FQDN or client ID (give one)."""

    hostname: Optional[str] = Field(
        None, description="Hostname or FQDN of the client to search for"
    )
    client_id: Optional[str] = Field(None, description="Velociraptor client ID, e.g. C.1234abcd")


class GetHuntResultsArgs(BaseModel):
    """Arguments for reading existing hunt results."""

    hunt_id: str = Field(..., description="Hunt ID, e.g. H.D8CNRTTL5AOMM")
    artifact: str = Field(
        ...,
        description="Artifact name, optionally with a source (e.g. Windows.System.Pslist or Artifact/Source)",
    )
    fields: str = Field("*", description="Comma-separated fields to return (default '*')")
    limit: Optional[int] = Field(
        None, description="Maximum rows to return (capped by VELOCIRAPTOR_MAX_ROWS)"
    )


class ListHuntsArgs(BaseModel):
    """Arguments for listing hunts."""

    limit: Optional[int] = Field(20, description="Maximum hunts to return, newest first")


class RunVQLQueryArgs(BaseModel):
    """Arguments for running VQL queries."""

    vql: str = Field(..., description="VQL (Velociraptor Query Language) query to execute")
    max_rows: Optional[int] = Field(None, description="Maximum number of rows to return")
    timeout: Optional[int] = Field(None, description="Query timeout in seconds")


class ListLinuxArtifactNamesArgs(BaseModel):
    """Arguments for listing only Linux artifact names (no parameters needed)."""

    pass


class ListWindowsArtifactNamesArgs(BaseModel):
    """Arguments for listing only Windows artifact names (no parameters needed)."""

    pass


class ListLinuxArtifactsArgs(BaseModel):
    """Arguments for listing Linux artifacts (no parameters needed)."""

    pass


class ListWindowsArtifactsArgs(BaseModel):
    """Arguments for listing Windows artifacts (no parameters needed)."""

    pass


class CollectArtifactArgs(BaseModel):
    """Arguments for collecting artifacts from a client."""

    client_id: str = Field(..., description="Velociraptor client ID to target for collection")
    artifact: str = Field(..., description="Name of the Velociraptor artifact to collect")
    parameters: str = Field(
        "",
        description="Comma-separated string of key='value' pairs to pass to the artifact",
    )


class GetCollectionResultsArgs(BaseModel):
    """Arguments for getting collection results."""

    client_id: str = Field(..., description="Velociraptor client ID where the collection was run")
    flow_id: str = Field(..., description="Flow ID returned from the initial collection")
    artifact: str = Field(
        ...,
        description="Name of the artifact collected (e.g., Windows.NTFS.MFT)",
    )
    fields: str = Field(
        "*",
        description="Comma-separated string of fields to return (default is '*')",
    )
    max_retries: int = Field(5, description="Number of times to retry if the flow hasn't finished")
    retry_delay: int = Field(5, description="Time in seconds to wait between retries")
    wait: bool = Field(
        True,
        description="Wait and retry until the flow finishes. False returns the current state at once "
        "(use for existing collections).",
    )
    limit: Optional[int] = Field(
        None, description="Maximum rows per artifact source (capped by VELOCIRAPTOR_MAX_ROWS)"
    )


class CollectArtifactDetailsArgs(BaseModel):
    """Arguments for getting detailed artifact information."""

    artifact_name: str = Field(
        ...,
        description="Name of the artifact to get details for (e.g., Windows.System.Users)",
    )


# Tool name -> (category, writes). `writes` marks tools that act on endpoints or can run arbitrary VQL;
# they are not registered when VELOCIRAPTOR_READ_ONLY is true. Unclassified tools count as writes.
TOOL_META: Dict[str, Tuple[str, bool]] = {
    "AuthenticateTool": ("auth", False),
    "GetAgentInfo": ("clients", False),
    "RunVQLQueryTool": ("vql", True),
    "ListLinuxArtifactNamesTool": ("artifacts", False),
    "ListWindowsArtifactNamesTool": ("artifacts", False),
    "ListLinuxArtifactsTool": ("artifacts", False),
    "ListWindowsArtifactsTool": ("artifacts", False),
    "FindArtifactDetailsTool": ("artifacts", False),
    "CollectArtifactDetailsTool": ("artifacts", False),
    "CollectArtifactTool": ("collections", True),
    "GetCollectionResultsTool": ("collections", False),
    "ListHuntsTool": ("hunts", False),
    "GetHuntResultsTool": ("hunts", False),
}


class BearerAuthMiddleware:
    """Require `Authorization: Bearer <MCP_AUTH_TOKEN>` on every HTTP path except /healthz."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.token = token.encode()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        header = dict(scope.get("headers") or []).get(b"authorization", b"")
        scheme, _, presented = header.partition(b" ")
        if scheme.lower() != b"bearer" or not hmac.compare_digest(presented.strip(), self.token):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error":"Unauthorized"}'})
            return
        await self.app(scope, receive, send)


class VelociraptorMCPServer:
    """Main MCP server for Velociraptor integration."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client: Optional[VelociraptorClient] = None
        self.app = FastMCP(name="Velociraptor MCP Server", version="0.2.0")

        # Register tools
        self._register_tools()

        @self.app.custom_route("/healthz", methods=["GET"], include_in_schema=False)
        async def healthz(_request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

    def _enabled(self, name: str) -> bool:
        """Whether a tool should be registered, given disabled tools, categories and read-only mode."""
        category, writes = TOOL_META.get(name, ("other", True))
        server = self.config.server
        if name in server.disabled_tools or category in server.disabled_categories:
            logger.info("Tool %s disabled by configuration", name)
            return False
        if server.read_only and writes:
            logger.info("Tool %s not registered: VELOCIRAPTOR_READ_ONLY is set", name)
            return False
        return True

    def _get_client(self) -> VelociraptorClient:
        """Get or create Velociraptor client."""
        if self._client is None:
            self._client = VelociraptorClient(self.config.velociraptor)
        return self._client

    def _register_tools(self) -> None:
        """Register all available tools."""

        if self._enabled("AuthenticateTool"):

            @self.app.tool(
                name="AuthenticateTool",
                description="Initialize and test connection to Velociraptor server. This tool requires no parameters and will establish a gRPC connection for subsequent API calls using the api.config.yaml file.",
            )
            async def authenticate_tool(args: AuthenticateArgs):
                """Initialize and test connection to Velociraptor server.

                This tool does not require any parameters. Simply call it to initialize
                the gRPC connection and test authentication with the Velociraptor server
                using the configured api.config.yaml file.

                Returns:
                    Success message with connection details or error message.
                """
                try:
                    client = self._get_client()
                    result = await client.authenticate()
                    return f"Authentication successful: {self._dumps(result)}"
                except Exception as e:
                    logger.error("Authentication failed: %s", e)
                    return f"Authentication failed: {str(e)}"

        if self._enabled("GetAgentInfo"):

            @self.app.tool(
                name="GetAgentInfo",
                description="Retrieve detailed information about a Velociraptor client by hostname or FQDN. This tool searches for a client using the provided hostname and returns comprehensive client details including ID, OS information, agent version, and connection status.",
            )
            async def get_agent_info_tool(args: GetAgentInfoArgs):
                """Return detailed information about a Velociraptor client by hostname.

                This tool searches for a client using the provided hostname or FQDN and returns
                detailed information including client ID, operating system details, agent version,
                and last seen timestamps.

                Args:
                    args: An object containing:
                        - hostname (required): Hostname or FQDN to search for

                Example usage:
                    {"args": {"hostname": "workstation-01"}}
                    {"args": {"hostname": "server.domain.com"}}

                Returns:
                    JSON object with client details or error message if not found.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Use the find_client_info method from the client
                    if bool(args.hostname) == bool(args.client_id):
                        raise ToolError("Provide exactly one of 'hostname' or 'client_id'.")
                    if args.client_id:
                        label, kind = args.client_id, "client_id"
                        client_info = await asyncio.to_thread(
                            client.find_client_by_id, args.client_id
                        )
                    else:
                        label, kind = args.hostname, "hostname"
                        client_info = await asyncio.to_thread(
                            client.find_client_info, args.hostname
                        )

                    if client_info is None:
                        return f"No client found with {kind}: {label}"

                    # Format the response
                    response_text = self._dumps(client_info)

                    return f"Client information for '{label}':\n{response_text}"
                except Exception as e:
                    logger.error("Failed to get agent info: %s", e)
                    raise ToolError(f"Error getting agent info: {str(e)}") from e

        if self._enabled("RunVQLQueryTool"):

            @self.app.tool(
                name="RunVQLQueryTool",
                description="Execute a VQL (Velociraptor Query Language) query on the Velociraptor server. This tool allows you to run custom VQL queries to retrieve information about clients, artifacts, hunts, or any other Velociraptor data. Requires 'vql' parameter with the query string.",
            )
            async def run_vql_query_tool(args: RunVQLQueryArgs):
                """Execute a VQL query on the Velociraptor server.

                VQL (Velociraptor Query Language) is a powerful query language that allows you to:
                - List and search clients: SELECT * FROM clients()
                - Query artifacts: SELECT * FROM source(artifact='Windows.System.Users')
                - Check flows: SELECT * FROM flows()
                - Hunt management: SELECT * FROM hunts()
                - And much more...

                Args:
                    args: An object containing:
                        - vql (required): VQL query string to execute
                        - max_rows (optional): Maximum number of rows to return
                        - timeout (optional): Query timeout in seconds

                Example usage:
                    {"args": {"vql": "SELECT client_id, os_info.hostname FROM clients() LIMIT 10"}}
                    {"args": {"vql": "SELECT * FROM flows() WHERE client_id = 'C.1234567890'"}}
                    {"args": {"vql": "SELECT name, description FROM artifacts() WHERE name =~ 'Windows'"}}

                Returns:
                    JSON array of query results with columns and data as returned by Velociraptor.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Execute the VQL query using the client's run_vql_query method
                    results = await asyncio.to_thread(
                        client.run_vql_query, args.vql, max_rows=args.max_rows, timeout=args.timeout
                    )

                    # Format the response
                    return self._fit_rows(results)
                except Exception as e:
                    logger.error("Failed to execute VQL query: %s", e)
                    raise ToolError(f"Error executing VQL query: {str(e)}") from e

        if self._enabled("ListLinuxArtifactNamesTool"):

            @self.app.tool(
                name="ListLinuxArtifactNamesTool",
                description="List only the names of available Linux artifacts in Velociraptor. This tool returns a simple list of artifact names for Linux client artifacts.",
            )
            async def list_linux_artifact_names_tool(args: ListLinuxArtifactNamesArgs):
                """List only the names of available Linux artifacts."""
                try:
                    client = self._get_client()
                    if client.stub is None:
                        await client.authenticate()
                    vql = "SELECT name FROM artifact_definitions() WHERE type =~ 'client' AND name =~ 'linux\\.'"
                    results = await asyncio.to_thread(client.run_vql_query, vql)
                    names = [r["name"] for r in results if "name" in r]
                    return self._fit_rows(names)
                except Exception as e:
                    logger.error("Failed to list Linux artifact names: %s", e)
                    raise ToolError(f"Error listing Linux artifact names: {str(e)}") from e

        if self._enabled("ListWindowsArtifactNamesTool"):

            @self.app.tool(
                name="ListWindowsArtifactNamesTool",
                description="List only the names of available Windows artifacts in Velociraptor. This tool returns a simple list of artifact names for Windows client artifacts.",
            )
            async def list_windows_artifact_names_tool(args: ListWindowsArtifactNamesArgs):
                """List only the names of available Windows artifacts."""
                try:
                    client = self._get_client()
                    if client.stub is None:
                        await client.authenticate()
                    vql = "SELECT name FROM artifact_definitions() WHERE type =~ 'client' AND name =~ '^windows\\.'"
                    results = await asyncio.to_thread(client.run_vql_query, vql)
                    names = [r["name"] for r in results if "name" in r]
                    return self._fit_rows(names)
                except Exception as e:
                    logger.error("Failed to list Windows artifact names: %s", e)
                    raise ToolError(f"Error listing Windows artifact names: {str(e)}") from e

        if self._enabled("ListLinuxArtifactsTool"):

            @self.app.tool(
                name="ListLinuxArtifactsTool",
                description="List available Linux artifacts in Velociraptor. This tool returns a summary of all Linux client artifacts including their names, descriptions, and required parameters.",
            )
            async def list_linux_artifacts_tool(args: ListLinuxArtifactsArgs):
                """List available Linux artifacts with their descriptions and parameters.

                This tool queries the Velociraptor server for all available Linux client artifacts
                and returns a structured summary including artifact names, short descriptions,
                and parameter requirements.

                Returns:
                    JSON array of Linux artifacts with name, short_description, and parameters.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # VQL query to get Linux artifacts
                    vql = """
                    LET params(data) = SELECT name FROM data
                    SELECT name, description, params(data=parameters) AS parameters
                    FROM artifact_definitions()
                    WHERE type =~ 'client' AND name =~ 'linux\\.'
                    """

                    # Helper function to shorten descriptions
                    def shorten(desc: str) -> str:
                        return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

                    # Execute the VQL query
                    results = await asyncio.to_thread(client.run_vql_query, vql)

                    # Process results to create summaries
                    summaries = []
                    for r in results:
                        summaries.append(
                            {
                                "name": r["name"],
                                "short_description": shorten(r.get("description", "")),
                                "parameters": [p["name"] for p in r.get("parameters", [])],
                            },
                        )

                    # Format the response
                    return self._fit_rows(summaries)
                except Exception as e:
                    logger.error("Failed to list Linux artifacts: %s", e)
                    raise ToolError(f"Error listing Linux artifacts: {str(e)}") from e

        if self._enabled("ListWindowsArtifactsTool"):

            @self.app.tool(
                name="ListWindowsArtifactsTool",
                description="List available Windows artifacts in Velociraptor. This tool returns a summary of all Windows client artifacts including their names, descriptions, and required parameters. Generally parameters that target filename regexs are more performant in NTFS queries: MFT, USN and can also be used to target top level folders. A Path glob is performant, and path regex is useful to specifically filter locations.",
            )
            async def list_windows_artifacts_tool(args: ListWindowsArtifactsArgs):
                """List available Windows artifacts with their descriptions and parameters.

                This tool queries the Velociraptor server for all available Windows client artifacts
                and returns a structured summary including artifact names, short descriptions,
                and parameter requirements.

                Generally parameters that target filename regexs are more performant in NTFS queries:
                MFT, USN and can also be used to target top level folders. A Path glob is performant,
                and path regex is useful to specifically filter locations.

                Returns:
                    JSON array of Windows artifacts with name, short_description, and parameters.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # VQL query to get Windows artifacts
                    vql = """
                    LET params(data) = SELECT name FROM data
                    SELECT name, description, params(data=parameters) AS parameters
                    FROM artifact_definitions()
                    WHERE type =~ 'client' AND name =~ '^windows\\.'
                    """

                    # Helper function to shorten descriptions
                    def shorten(desc: str) -> str:
                        return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

                    # Execute the VQL query
                    results = await asyncio.to_thread(client.run_vql_query, vql)

                    # Process results to create summaries
                    summaries = []
                    for r in results:
                        summaries.append(
                            {
                                "name": r["name"],
                                "short_description": shorten(r.get("description", "")),
                                "parameters": [p["name"] for p in r.get("parameters", [])],
                            },
                        )

                    # Format the response
                    return self._fit_rows(summaries)
                except Exception as e:
                    logger.error("Failed to list Windows artifacts: %s", e)
                    raise ToolError(f"Error listing Windows artifacts: {str(e)}") from e

        if self._enabled("FindArtifactDetailsTool"):

            @self.app.tool(
                name="FindArtifactDetailsTool",
                description="Find a Velociraptor artifact's name, description, and parameters by artifact name. Returns a summary for the specified artifact.",
            )
            async def find_artifact_details_tool(args: CollectArtifactDetailsArgs):
                """Find a Velociraptor artifact's name, description, and parameters by artifact name.

                Args:
                    args: An object containing:
                        - artifact_name (required): Name of the artifact to get details for

                Returns:
                    JSON object with artifact name, description, and parameters.
                """
                try:
                    client = self._get_client()
                    if client.stub is None:
                        await client.authenticate()
                    vql = """
                    LET params(data) = SELECT name, description, type, default FROM data
                    SELECT name, description, params(data=parameters) AS parameters
                    FROM artifact_definitions()
                    WHERE name = McpArtifactName
                    """
                    results = await asyncio.to_thread(
                        client.run_vql_query, vql, env={"McpArtifactName": args.artifact_name}
                    )
                    if not results:
                        return f"No artifact found with name: {args.artifact_name}"
                    artifact = results[0]
                    # Only keep relevant parameter fields
                    parameters = [
                        {
                            "name": p.get("name"),
                            "description": p.get("description", ""),
                            "type": p.get("type", ""),
                            "default": p.get("default", None),
                        }
                        for p in artifact.get("parameters", [])
                    ]
                    summary = {
                        "name": artifact.get("name"),
                        "description": artifact.get("description", ""),
                        "parameters": parameters,
                    }
                    response_text = self._dumps(summary)
                    return self._safe_truncate(response_text)
                except Exception as e:
                    logger.error("Failed to find artifact details: %s", e)
                    raise ToolError(f"Error finding artifact details: {str(e)}") from e

        if self._enabled("CollectArtifactTool"):

            @self.app.tool(
                name="CollectArtifactTool",
                description="Collect a Velociraptor artifact from a client. This tool allows you to collect specific artifacts from a target client by specifying the client ID and artifact name. Optionally, you can provide parameters for the artifact collection.",
            )
            async def collect_artifact_tool(args: CollectArtifactArgs):
                """Collect a Velociraptor artifact from a client.

                This tool collects a specific artifact from a target client. You must provide
                the client ID and artifact name. Optionally, you can provide parameters for
                the artifact collection in the form of key='value' pairs.

                Args:
                    args: An object containing:
                        - client_id (required): Velociraptor client ID to target for collection
                        - artifact (required): Name of the Velociraptor artifact to collect
                        - parameters (optional): Comma-separated string of key='value' pairs

                Example usage:
                    {"args": {"client_id": "C.1234567890", "artifact": "Windows.System.Users"}}
                    {"args": {"client_id": "C.0987654321", "artifact": "Linux.System.Uptime", "parameters": "format='seconds'"}}

                Returns:
                    JSON object with collection information including flow_id and status.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Start the collection using the client's start_collection method
                    response = await asyncio.to_thread(
                        client.start_collection,
                        args.client_id,
                        args.artifact,
                        args.parameters,
                    )

                    # Ensure the response contains the flow ID
                    if (
                        not isinstance(response, list)
                        or not response
                        or "flow_id" not in response[0]
                    ):
                        raise ToolError(f"Failed to start collection: {self._dumps(response)}")

                    # Format the response
                    response_text = self._dumps(response[0])

                    return f"Collection started successfully:\n{response_text}"
                except Exception as e:
                    logger.error("Failed to collect artifact: %s", e)
                    raise ToolError(f"Error collecting artifact: {str(e)}") from e

        if self._enabled("GetCollectionResultsTool"):

            @self.app.tool(
                name="GetCollectionResultsTool",
                description="Retrieve Velociraptor collection results for a given client, flow ID, and artifact. This tool waits and retries if the flow hasn't finished or if no results are immediately available. Use this after starting a collection with CollectArtifactTool.",
            )
            async def get_collection_results_tool(args: GetCollectionResultsArgs):
                """Retrieve Velociraptor collection results for a given client, flow ID, and artifact.

                This tool retrieves results from a previously started collection. It will wait and retry
                if the flow hasn't finished or if no results are immediately available. This is typically
                used after starting a collection with CollectArtifactTool.

                Args:
                    args: An object containing:
                        - client_id (required): Velociraptor client ID where the collection was run
                        - flow_id (required): Flow ID returned from the initial collection
                        - artifact (required): Name of the artifact collected (e.g., Windows.NTFS.MFT)
                        - fields (optional): Comma-separated string of fields to return (default is '*')
                        - max_retries (optional): Number of times to retry if the flow hasn't finished (default: 10)
                        - retry_delay (optional): Time in seconds to wait between retries (default: 30)

                Example usage:
                    {"args": {"client_id": "C.1234567890", "flow_id": "F.ABC123", "artifact": "Windows.System.Users"}}
                    {"args": {"client_id": "C.0987654321", "flow_id": "F.DEF456", "artifact": "Linux.System.Uptime", "fields": "Uptime,BootTime"}}

                Returns:
                    JSON array of collection results or status message if still running/failed.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # First, get artifact details to check if it has multiple sources
                    artifact_details_vql = "SELECT name,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName"
                    artifact_details = await asyncio.to_thread(
                        client.run_vql_query,
                        artifact_details_vql,
                        env={"McpArtifactName": args.artifact},
                    )

                    source_names = []
                    if artifact_details and len(artifact_details) > 0:
                        source_names = artifact_details[0].get("source_names", [])

                    # Filter out empty or None source names
                    valid_source_names = [name for name in source_names if name and name.strip()]

                    # Determine the artifact names to check (with sources if they exist)
                    artifacts_to_check = []
                    if valid_source_names and len(valid_source_names) > 0:
                        # Artifact has multiple sources, check each one
                        for source_name in valid_source_names:
                            artifacts_to_check.append(f"{args.artifact}/{source_name}")
                    else:
                        # Artifact has no valid sources, use the artifact name directly
                        artifacts_to_check.append(args.artifact)

                    logger.info("Checking artifacts: %s", artifacts_to_check)

                    # Retry logic to wait for collection completion
                    all_results = {}
                    incomplete_sources = []

                    attempts = max(args.max_retries, 1) if args.wait else 1
                    for attempt in range(attempts):
                        logger.info(
                            "Checking collection status (attempt %d/%d) for flow %s",
                            attempt + 1,
                            attempts,
                            args.flow_id,
                        )

                        # Check status for each artifact (with sources)
                        all_finished = True
                        incomplete_sources = []  # Reset incomplete sources for this attempt

                        for artifact_with_source in artifacts_to_check:
                            if (
                                artifact_with_source not in all_results
                            ):  # Only check if we haven't gotten results yet
                                status = await asyncio.to_thread(
                                    client.get_flow_status,
                                    args.client_id,
                                    args.flow_id,
                                    artifact_with_source,
                                )
                                logger.info("Flow status for %s: %s", artifact_with_source, status)

                                if status == "FINISHED":
                                    # Get the results for this artifact/source
                                    results = await asyncio.to_thread(
                                        client.get_flow_results,
                                        args.client_id,
                                        args.flow_id,
                                        artifact_with_source,
                                        args.fields,
                                        **({"max_rows": args.limit} if args.limit else {}),
                                    )
                                    all_results[artifact_with_source] = results
                                    logger.info(
                                        "Got results for %s: %d records",
                                        artifact_with_source,
                                        len(results) if results else 0,
                                    )
                                else:
                                    all_finished = False
                                    incomplete_sources.append(artifact_with_source)

                        # If all artifacts/sources are finished, return the results
                        if all_finished:
                            return self._format_collection_results(
                                args,
                                artifacts_to_check,
                                all_results,
                                incomplete_sources=[],
                            )

                        # If this is the last attempt and we have some results, return partial results
                        if attempt == attempts - 1 and all_results:
                            logger.info(
                                "Max retries reached, returning partial results. Incomplete sources: %s",
                                incomplete_sources,
                            )
                            return self._format_collection_results(
                                args,
                                artifacts_to_check,
                                all_results,
                                incomplete_sources,
                            )

                        # If not all finished and not the last attempt, wait before retrying
                        if attempt < attempts - 1:
                            logger.info(
                                "Some artifacts not finished, waiting %d seconds before retry",
                                args.retry_delay,
                            )
                            await asyncio.sleep(args.retry_delay)

                    # If we've exhausted retries and have no results
                    if all_results:
                        # This shouldn't happen due to the check above, but just in case
                        return self._format_collection_results(
                            args,
                            artifacts_to_check,
                            all_results,
                            incomplete_sources,
                        )
                    else:
                        return (
                            f"Collection results not available after {attempts} retries. "
                            f"Flow {args.flow_id} may still be running or may have failed. "
                            f"Try again later or check the Velociraptor UI for flow status. "
                            f"Checked artifacts: {artifacts_to_check}"
                        )

                except Exception as e:
                    logger.error("Failed to get collection results: %s", e)
                    raise ToolError(f"Error getting collection results: {str(e)}") from e

        if self._enabled("ListHuntsTool"):

            @self.app.tool(
                name="ListHuntsTool",
                description="List Velociraptor hunts, newest first, with hunt ID, state, artifacts and client counts. Read-only.",
            )
            async def list_hunts_tool(args: ListHuntsArgs):
                """List hunts so their results can be read with GetHuntResultsTool."""
                try:
                    client = self._get_client()
                    if client.stub is None:
                        await client.authenticate()
                    hunts = await asyncio.to_thread(client.list_hunts, max_rows=args.limit)
                    return self._fit_rows(hunts)
                except Exception as e:
                    logger.error("Failed to list hunts: %s", e)
                    raise ToolError(f"Error listing hunts: {str(e)}") from e

        if self._enabled("GetHuntResultsTool"):

            @self.app.tool(
                name="GetHuntResultsTool",
                description="Read the existing results of a Velociraptor hunt for one artifact. Artifacts with several sources must be given as Artifact/Source (see CollectArtifactDetailsTool for source names). Read-only: it runs nothing on endpoints. Use 'fields' and 'limit' to keep results small.",
            )
            async def get_hunt_results_tool(args: GetHuntResultsArgs):
                """Read existing hunt results.

                Example usage:
                    {"args": {"hunt_id": "H.D8CNRTTL5AOMM", "artifact": "Windows.System.Pslist", "fields": "Name, Pid", "limit": 50}}
                """
                try:
                    client = self._get_client()
                    if client.stub is None:
                        await client.authenticate()
                    rows = await asyncio.to_thread(
                        client.get_hunt_results,
                        args.hunt_id,
                        args.artifact,
                        args.fields,
                        max_rows=args.limit,
                    )
                    header = f"Hunt {args.hunt_id} results for {args.artifact}: {len(rows)} rows"
                    return f"{header}\n{self._fit_rows(rows)}"
                except Exception as e:
                    logger.error("Failed to get hunt results: %s", e)
                    raise ToolError(f"Error getting hunt results: {str(e)}") from e

        if self._enabled("CollectArtifactDetailsTool"):

            @self.app.tool(
                name="CollectArtifactDetailsTool",
                description="Get detailed information about a specific Velociraptor artifact including its description, parameters, and source code. This tool helps you understand what an artifact does and what parameters it requires before collection.",
            )
            async def collect_artifact_details_tool(args: CollectArtifactDetailsArgs):
                """Get detailed information about a specific Velociraptor artifact.

                This tool retrieves comprehensive details about a specific artifact including:
                - Full description of what the artifact does
                - All available parameters and their descriptions
                - Source code/VQL that defines the artifact
                - Parameter types and default values

                This is useful for understanding an artifact before collecting it, or for
                debugging collection issues.

                Args:
                    args: An object containing:
                        - artifact_name (required): Name of the artifact to get details for

                Example usage:
                    {"args": {"artifact_name": "Windows.System.Users"}}
                    {"args": {"artifact_name": "Linux.Network.Netstat"}}
                    {"args": {"artifact_name": "Windows.NTFS.MFT"}}

                Returns:
                    JSON object with detailed artifact information including description, parameters, and source.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Execute the VQL query to get artifact details
                    vql = "SELECT name,description,parameters,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName"
                    results = await asyncio.to_thread(
                        client.run_vql_query, vql, env={"McpArtifactName": args.artifact_name}
                    )

                    if not results:
                        return f"No artifact found with name: {args.artifact_name}"

                    # Get the first (and should be only) result
                    artifact_details = results[0]

                    # Get source names - this is already a list of strings
                    source_names = artifact_details.get("source_names", [])

                    # Format the response for better readability
                    formatted_details = {
                        "name": artifact_details.get("name", ""),
                        "description": artifact_details.get("description", ""),
                        "parameters": artifact_details.get("parameters", []),
                        "source_names": source_names,
                        "source_count": len(source_names) if source_names else 0,
                    }

                    response_text = self._dumps(formatted_details)

                    return f"Artifact details for '{args.artifact_name}':\n{response_text}"

                except Exception as e:
                    logger.error("Failed to get artifact details: %s", e)
                    raise ToolError(f"Error getting artifact details: {str(e)}") from e

    @staticmethod
    def _dumps(value) -> str:
        """Compact JSON for tool output."""
        return json.dumps(value, separators=(",", ":"), default=str)

    def _safe_truncate(self, text: str, max_length: Optional[int] = None) -> str:
        """Cut text to the output limit, saying how much was cut."""
        max_length = max_length or self.config.server.max_output_chars
        if len(text) <= max_length:
            return text
        return (
            text[:max_length] + f"\n\n[truncated: showing {max_length} of {len(text)} characters]"
        )

    def _fit_rows(self, rows: list) -> str:
        """Compact JSON array of rows, dropping whole rows to fit the output limit.

        When rows are dropped, a final line states how many rows are shown out of how many and the
        original size, so a partial answer is never mistaken for a complete one.
        """
        limit = self.config.server.max_output_chars
        text = self._dumps(rows)
        if len(text) <= limit or not isinstance(rows, list) or not rows:
            return self._safe_truncate(text, limit)
        original_rows, original_chars = len(rows), len(text)
        kept = list(rows)
        while len(kept) > 1:
            kept = kept[: max(len(kept) * 3 // 4, len(kept) - 1)]
            text = self._dumps(kept)
            if len(text) <= limit - 200:
                break
        else:
            text = self._safe_truncate(self._dumps(kept), limit - 200)
        return (
            f"{text}\n[truncated: showing {len(kept)} of {original_rows} rows "
            f"({original_chars} characters); request fewer fields or a lower limit]"
        )

    def _format_collection_results(self, args, artifacts_to_check, all_results, incomplete_sources):
        """Format collection results with support for partial results."""
        if not all_results:
            return f"Flow {args.flow_id} completed but no results were found for artifact {args.artifact}"

        # Determine if we have partial results
        has_incomplete_sources = bool(incomplete_sources)

        if len(artifacts_to_check) == 1:
            # Single artifact/source
            artifact_name = artifacts_to_check[0]
            results = all_results.get(artifact_name, [])
            status_msg = ""
            if has_incomplete_sources:
                status_msg = f"\n\n⚠️  WARNING: This collection timed out. Some sources may still be running: {', '.join(incomplete_sources)}"

            return f"Collection results for flow {args.flow_id} (artifact: {artifact_name}):\n{self._fit_rows(results or [])}{status_msg}"
        else:
            # Multiple sources - combine results
            completed_count = len(all_results)
            total_count = len(artifacts_to_check)

            combined_response = {
                "flow_id": args.flow_id,
                "artifact": args.artifact,
                "sources": all_results,
                "total_records": sum(
                    len(results) if results else 0 for results in all_results.values()
                ),
                "completed_sources": completed_count,
                "total_sources": total_count,
            }

            if has_incomplete_sources:
                combined_response["incomplete_sources"] = incomplete_sources
                combined_response["status"] = "partial_results"
            else:
                combined_response["status"] = "complete"

            response_text = self._dumps(combined_response)

            status_msg = ""
            if has_incomplete_sources:
                status_msg = (
                    f"\n\n⚠️  WARNING: Partial results returned after timeout. "
                    f"Completed {completed_count}/{total_count} sources. "
                    f"Incomplete sources: {', '.join(incomplete_sources)}. "
                    f"You may want to check these sources later or increase retry settings."
                )

            collection_type = (
                "with partial results" if has_incomplete_sources else "with multiple sources"
            )
            return f"Collection results for flow {args.flow_id} (artifact: {args.artifact} {collection_type}):\n{self._safe_truncate(response_text)}{status_msg}"

    def _normalize_args(self, raw_args, model_class):
        """Normalize arguments to handle both direct and wrapped formats."""
        if isinstance(raw_args, dict):
            # If it has an 'args' key, use that
            if "args" in raw_args:
                return model_class(**raw_args["args"])
            # Otherwise, assume the dict itself contains the arguments
            else:
                return model_class(**raw_args)
        # If it's already a model instance, return as-is
        elif hasattr(raw_args, "__dict__"):
            return raw_args
        else:
            # Fallback to empty model
            return model_class()

    def http_app(self):
        """Streamable HTTP app at /mcp with bearer-token auth and an open /healthz."""
        token = self.config.server.auth_token
        if not token:
            raise ValueError("MCP_AUTH_TOKEN is required for the HTTP transport")
        return self.app.http_app(
            path="/mcp", middleware=[Middleware(BearerAuthMiddleware, token=token)]
        )

    def start(self, host: str = None, port: int = None) -> None:
        """Start the MCP server on the configured transport (stdio by default)."""
        server = self.config.server
        logger.info("SSL Verify: %s", self.config.velociraptor.ssl_verify)

        if server.transport == "http":
            host = host or server.host
            port = port or server.port
            logger.info(
                "Starting Velociraptor MCP Server (HTTP transport) on %s:%s/mcp", host, port
            )
            uvicorn.run(self.http_app(), host=host, port=port, log_level=server.log_level.lower())
            return

        # stdio is what MCP clients use when they launch the server as a subprocess (.mcp.json).
        logger.info("Starting Velociraptor MCP Server (stdio transport)")
        self.app.run()

    async def close(self) -> None:
        """Close the server and cleanup resources."""
        if self._client:
            await self._client.close()


def create_server(config: Config = None) -> VelociraptorMCPServer:
    """Factory function to create a VelociraptorMCPServer instance."""
    if config is None:
        config = Config.from_env()

    config.validate()
    config.setup_logging()

    return VelociraptorMCPServer(config)
