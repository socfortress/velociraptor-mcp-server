"""
Velociraptor client for API communication.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Mapping, Optional

import grpc
import yaml
from pyvelociraptor import api_pb2, api_pb2_grpc

from .config import VelociraptorConfig
from .exceptions import VelociraptorAPIError, VelociraptorAuthenticationError

logger = logging.getLogger(__name__)

# Untrusted values never go into VQL text. They are passed as query environment variables
# (VQLCollectorArgs.env) and referenced by name, so a crafted hostname, artifact or field can't change
# the query. Variable names carry an `Mcp` prefix so they never collide with column names or aliases
# (a variable called `Hostname` would be shadowed by `... AS Hostname`). Identifiers that must appear in the text (field lists) are validated instead.
_CLIENT_ID = re.compile(r"^(C\.[0-9a-fA-F]+|server)$")
_FLOW_ID = re.compile(r"^F\.[A-Za-z0-9]+(\.[A-Za-z0-9]+)?$")  # hunt flows end in ".H"
_HUNT_ID = re.compile(r"^H\.[A-Za-z0-9]+$")
_ARTIFACT = re.compile(r"^[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\- ]+)?$")
_FIELDS = re.compile(r"^\s*(\*|[A-Za-z_][\w.]*(\s*,\s*[A-Za-z_][\w.]*)*)\s*$")
_PARAM = re.compile(r"\s*([A-Za-z_]\w*)\s*=\s*'([^']*)'\s*(?:,|$)")


def _check(value: str, pattern: "re.Pattern[str]", what: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def parse_parameters(parameters: str) -> Dict[str, str]:
    """Parse the tools' "key='value', key2='value2'" parameter string into a dict, strictly."""
    result: Dict[str, str] = {}
    text = (parameters or "").strip()
    pos = 0
    while pos < len(text):
        match = _PARAM.match(text, pos)
        if not match or match.end() == pos:
            raise ValueError(f"invalid artifact parameters near: {text[pos:pos + 40]!r}")
        result[match.group(1)] = match.group(2)
        pos = match.end()
    return result


class VelociraptorClient:
    """Client for communicating with Velociraptor API via gRPC."""

    def __init__(self, config: VelociraptorConfig):
        """Initialize the Velociraptor client.

        Args:
            config: Velociraptor configuration object
        """
        self.config = config
        self.stub: Optional[api_pb2_grpc.APIStub] = None
        self._channel: Optional[grpc.Channel] = None

    async def authenticate(self) -> Dict[str, Any]:
        """Initialize gRPC connection and test authentication.

        Returns:
            Dictionary with connection status and server information

        Raises:
            VelociraptorAuthenticationError: If authentication fails
            VelociraptorAPIError: If API connection fails
        """
        try:
            # For Velociraptor, we need to use a config file or API key
            # If config.api_key is a path to a config file, load it
            if self.config.api_key.endswith(".yaml") or self.config.api_key.endswith(".yml"):
                config_path = self.config.api_key
                if not os.path.exists(config_path):
                    raise VelociraptorAuthenticationError(f"Config file not found: {config_path}")

                # Load the API config file
                with open(config_path, "r") as f:
                    api_config = yaml.safe_load(f)

                # Validate required fields
                required_fields = [
                    "ca_certificate",
                    "client_private_key",
                    "client_cert",
                    "api_connection_string",
                ]
                for field in required_fields:
                    if field not in api_config:
                        raise VelociraptorAuthenticationError(
                            f"Missing required field in config: {field}",
                        )

                # Create SSL credentials
                creds = grpc.ssl_channel_credentials(
                    root_certificates=api_config["ca_certificate"].encode("utf-8"),
                    private_key=api_config["client_private_key"].encode("utf-8"),
                    certificate_chain=api_config["client_cert"].encode("utf-8"),
                )

                # Channel options
                channel_opts = (("grpc.ssl_target_name_override", "VelociraptorServer"),)

                # Create secure channel
                self._channel = grpc.secure_channel(
                    api_config["api_connection_string"],
                    creds,
                    options=channel_opts,
                )

                # Create stub
                self.stub = api_pb2_grpc.APIStub(self._channel)

                # Test the connection with a simple query
                test_request = api_pb2.VQLCollectorArgs(
                    Query=[api_pb2.VQLRequest(VQL="SELECT * FROM info()")],
                )

                # Try to execute a test query
                results = []
                for resp in self.stub.Query(test_request):
                    if hasattr(resp, "error") and resp.error:
                        raise VelociraptorAPIError(f"Velociraptor API error: {resp.error}")
                    if hasattr(resp, "Response") and resp.Response:
                        results.extend(json.loads(resp.Response))

                return {
                    "status": "authenticated",
                    "connection_type": "gRPC",
                    "server_url": api_config["api_connection_string"],
                    "test_query_result": results,
                    "message": "Successfully connected to Velociraptor server",
                }

            else:
                # If it's not a config file path, treat it as a direct API key
                # This would require implementing HTTP API authentication
                # For now, we'll raise an error suggesting to use config file
                raise VelociraptorAuthenticationError(
                    "Direct API key authentication not yet implemented. "
                    "Please provide a path to an api.config.yaml file in the VELOCIRAPTOR_API_KEY environment variable.",
                )

        except grpc.RpcError as e:
            logger.error("gRPC error during authentication: %s", e)
            raise VelociraptorAuthenticationError(f"gRPC connection failed: {e}")
        except Exception as e:
            logger.error("Authentication failed: %s", e)
            if isinstance(e, (VelociraptorAuthenticationError, VelociraptorAPIError)):
                raise
            raise VelociraptorAuthenticationError(f"Authentication failed: {e}")

    def run_vql_query(
        self,
        vql: str,
        env: Optional[Mapping[str, str]] = None,
        max_rows: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a VQL query on the Velociraptor server.

        Args:
            vql: VQL query string to execute
            env: Query variables, referenced by name in `vql` (used for every untrusted value)
            max_rows: Row cap; never more than the configured `max_rows`
            timeout: Query timeout in seconds; never more than the configured `timeout`

        Returns:
            List of result dictionaries (at most the row cap)

        Raises:
            VelociraptorAPIError: If query execution fails
            RuntimeError: If stub is not initialized
        """
        if self.stub is None:
            raise RuntimeError("Stub not initialized. Call authenticate() first.")

        cap = self.config.max_rows
        if max_rows is not None and max_rows > 0:
            cap = min(cap, max_rows)
        deadline = self.config.timeout
        if timeout is not None and timeout > 0:
            deadline = min(deadline, timeout)

        try:
            logger.info("Executing VQL query: %s", vql)
            request = api_pb2.VQLCollectorArgs(
                Query=[api_pb2.VQLRequest(VQL=vql)],
                env=[api_pb2.VQLEnv(key=k, value=str(v)) for k, v in (env or {}).items()],
                max_row=cap,
                timeout=deadline,
            )
            results: List[Dict[str, Any]] = []
            stream = self.stub.Query(request, timeout=deadline + 5)
            for resp in stream:
                if hasattr(resp, "error") and resp.error:
                    raise VelociraptorAPIError(f"Velociraptor API error: {resp.error}")
                if hasattr(resp, "Response") and resp.Response:
                    results.extend(json.loads(resp.Response))
                if len(results) >= cap:
                    # Stop reading; cancel the server-side query when the stream supports it.
                    if hasattr(stream, "cancel"):
                        stream.cancel()
                    break

            return results[:cap]

        except grpc.RpcError as e:
            logger.error("gRPC error during query execution: %s", e)
            raise VelociraptorAPIError(f"Query execution failed: {e}")
        except VelociraptorAPIError:
            raise
        except Exception as e:
            logger.error("Query execution failed: %s", e)
            raise VelociraptorAPIError(f"Query execution failed: {e}")

    def close(self):
        """Close the gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self.stub = None

    # Helper methods based on the provided examples

    def find_client_info(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Find client information by hostname or FQDN (exact, case-sensitive match)."""
        vql = (
            "SELECT client_id,"
            "timestamp(epoch=first_seen_at) as FirstSeen,"
            "timestamp(epoch=last_seen_at) as LastSeen,"
            "os_info.hostname as Hostname,"
            "os_info.fqdn as Fqdn,"
            "os_info.system as OSType,"
            "os_info.release as OS,"
            "os_info.machine as Machine,"
            "agent_information.version as AgentVersion "
            "FROM clients() WHERE os_info.hostname = McpHostname OR os_info.fqdn = McpHostname "
            "ORDER BY LastSeen DESC LIMIT 1"
        )

        result = self.run_vql_query(vql, env={"McpHostname": hostname})
        if not result:
            return None
        return result[0]

    def find_client_by_id(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Find client information by client ID (e.g. C.1234abcd)."""
        vql = (
            "SELECT client_id,"
            "timestamp(epoch=first_seen_at) as FirstSeen,"
            "timestamp(epoch=last_seen_at) as LastSeen,"
            "os_info.hostname as Hostname,"
            "os_info.fqdn as Fqdn,"
            "os_info.system as OSType,"
            "os_info.release as OS,"
            "os_info.machine as Machine,"
            "agent_information.version as AgentVersion "
            "FROM clients(client_id=McpClientId) LIMIT 1"
        )
        result = self.run_vql_query(
            vql, env={"McpClientId": _check(client_id, _CLIENT_ID, "client_id")}
        )
        if not result:
            return None
        return result[0]

    def get_flow_state(self, client_id: str, flow_id: str) -> Optional[str]:
        """Overall flow state from flows(): FINISHED, RUNNING, ERROR, or None if the flow is unknown."""
        rows = self.run_vql_query(
            "SELECT state FROM flows(client_id=McpClientId, flow_id=McpFlowId)",
            env={
                "McpClientId": _check(client_id, _CLIENT_ID, "client_id"),
                "McpFlowId": _check(flow_id, _FLOW_ID, "flow_id"),
            },
            max_rows=1,
        )
        return rows[0].get("state") if rows else None

    def get_hunt_results(
        self,
        hunt_id: str,
        artifact: str,
        fields: str = "*",
        max_rows: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Read existing results of a hunt for one artifact (or `Artifact/Source`). Runs no new VQL on endpoints."""
        # Multi-source artifacts need the source inside the artifact name ("Artifact/Source"); on
        # Velociraptor 0.76 the separate `source=` argument returns no rows.
        vql = (
            f"SELECT {_check(fields, _FIELDS, 'fields').strip()} "
            "FROM hunt_results(hunt_id=McpHuntId, artifact=McpArtifact)"
        )
        env = {
            "McpHuntId": _check(hunt_id, _HUNT_ID, "hunt_id"),
            "McpArtifact": _check(artifact, _ARTIFACT, "artifact"),
        }
        return self.run_vql_query(vql, env=env, max_rows=max_rows)

    def list_hunts(self, max_rows: Optional[int] = None) -> List[Dict[str, Any]]:
        """List hunts, newest first, with their artifacts, state and client counts."""
        vql = (
            "SELECT hunt_id, hunt_description AS description, state, artifacts, "
            "timestamp(epoch=create_time) AS created, "
            "stats.total_clients_scheduled AS clients_scheduled, "
            "stats.total_clients_with_results AS clients_with_results "
            "FROM hunts() ORDER BY created DESC"
        )
        return self.run_vql_query(vql, max_rows=max_rows)

    def start_collection(
        self,
        client_id: str,
        artifact: str,
        parameters: str = "",
    ) -> List[Dict[str, Any]]:
        """Start a collection on a client.

        Args:
            client_id: Target client ID
            artifact: Artifact to collect
            parameters: "key='value', ..." pairs passed to the artifact

        Returns:
            Collection information
        """
        vql = (
            "LET collection <= collect_client(urgent='TRUE', client_id=McpClientId, "
            "artifacts=McpArtifact, env=parse_json(data=McpParams)) "
            "SELECT flow_id,request.artifacts as artifacts,request.specs[0] as specs "
            "FROM foreach(row=collection)"
        )
        env = {
            "McpClientId": _check(client_id, _CLIENT_ID, "client_id"),
            "McpArtifact": _check(artifact, _ARTIFACT, "artifact"),
            "McpParams": json.dumps(parse_parameters(parameters)),
        }
        return self.run_vql_query(vql, env=env)

    def get_flow_status(self, client_id: str, flow_id: str, artifact: str) -> str:
        """Get the status of a flow: "FINISHED", "RUNNING" or "ERROR"."""
        vql = (
            "SELECT * FROM flow_logs(client_id=McpClientId, flow_id=McpFlowId) "
            "WHERE message =~ McpDonePattern LIMIT 100"
        )

        try:
            state = self.get_flow_state(client_id, flow_id)
            if state in ("FINISHED", "ERROR"):
                return state
            env = {
                "McpClientId": _check(client_id, _CLIENT_ID, "client_id"),
                "McpFlowId": _check(flow_id, _FLOW_ID, "flow_id"),
                "McpDonePattern": "^Collection " + re.escape(_check(artifact, _ARTIFACT, "artifact"))
                + " is done after",
            }
            results = self.run_vql_query(vql, env=env)
            logger.info("Flow status query results: %s", results)
            if results and isinstance(results, list) and len(results) > 0:
                return "FINISHED"
            return "RUNNING"
        except Exception as e:
            logger.error("Error checking flow status: %s", e)
            return "ERROR"

    def get_flow_results(
        self,
        client_id: str,
        flow_id: str,
        artifact: str,
        fields: str = "*",
        max_rows: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get results from a completed flow (at most the configured row cap)."""
        vql = (
            f"SELECT {_check(fields, _FIELDS, 'fields').strip()} "
            "FROM source(client_id=McpClientId, flow_id=McpFlowId, artifact=McpArtifact)"
        )
        env = {
            "McpClientId": _check(client_id, _CLIENT_ID, "client_id"),
            "McpFlowId": _check(flow_id, _FLOW_ID, "flow_id"),
            "McpArtifact": _check(artifact, _ARTIFACT, "artifact"),
        }
        return self.run_vql_query(vql, env=env, max_rows=max_rows)

    def realtime_collection(
        self,
        client_id: str,
        artifact: str,
        parameters: str = "",
        fields: str = "*",
        result_scope: str = "",
    ) -> List[Dict[str, Any]]:
        """Perform a realtime collection and wait for results."""
        source = artifact + result_scope
        vql = (
            "LET collection <= collect_client(urgent='TRUE', client_id=McpClientId, "
            "artifacts=McpArtifact, env=parse_json(data=McpParams)) "
            "LET get_monitoring = SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') "
            "WHERE FlowId = collection.flow_id LIMIT 1 "
            "LET get_results = SELECT * FROM source(client_id=collection.request.client_id, "
            "flow_id=collection.flow_id, artifact=McpSource) "
            f"SELECT {_check(fields, _FIELDS, 'fields').strip()} "
            "FROM foreach(row=get_monitoring, query=get_results)"
        )
        env = {
            "McpClientId": _check(client_id, _CLIENT_ID, "client_id"),
            "McpArtifact": _check(artifact, _ARTIFACT, "artifact"),
            "McpSource": _check(source, _ARTIFACT, "artifact source"),
            "McpParams": json.dumps(parse_parameters(parameters)),
        }
        return self.run_vql_query(vql, env=env)

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close()
