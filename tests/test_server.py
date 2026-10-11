"""
Tests for the main server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from velociraptor_mcp_server.config import Config
from velociraptor_mcp_server.server import VelociraptorMCPServer, create_server


class TestVelociraptorMCPServer:
    """args = RunVQLQueryArgs(vql="SELECT * FROM clients() LIMIT 5")

    # Execute the tool
    result = await run_vql_query_tool.run(args) Velociraptor MCP server."""

    def test_init(self, config):
        """Test VelociraptorMCPServer initialization."""
        server = VelociraptorMCPServer(config)

        assert server.config == config
        assert server._client is None
        assert server.app is not None
        assert server.app.name == "Velociraptor MCP Server"

    def test_get_client(self, config):
        """Test _get_client method."""
        server = VelociraptorMCPServer(config)

        # First call should create client
        client1 = server._get_client()
        assert client1 is not None
        assert server._client is client1

        # Second call should return same client
        client2 = server._get_client()
        assert client2 is client1

    def test_safe_truncate_short_text(self, config):
        """Test _safe_truncate with short text."""
        server = VelociraptorMCPServer(config)

        short_text = "This is a short text"
        result = server._safe_truncate(short_text)

        assert result == short_text

    def test_safe_truncate_long_text(self, config):
        """Test _safe_truncate with long text."""
        server = VelociraptorMCPServer(config)

        long_text = "A" * 50000  # 50k characters
        result = server._safe_truncate(long_text, max_length=1000)

        assert len(result) > 1000  # Should include truncation message
        assert result.startswith("A" * 1000)
        assert "truncated" in result

    @pytest.mark.asyncio
    async def test_close(self, config):
        """Test server close method."""
        server = VelociraptorMCPServer(config)

        # Mock client
        mock_client = Mock()
        mock_client.close = AsyncMock()
        server._client = mock_client

        await server.close()

        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_no_client(self, config):
        """Test server close method with no client."""
        server = VelociraptorMCPServer(config)

        # Should not raise an exception
        await server.close()

    @pytest.mark.asyncio
    async def test_authenticate_tool_registration(self, config):
        """Test that AuthenticateTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "AuthenticateTool" in tool_names

    @pytest.mark.asyncio
    async def test_authenticate_tool_disabled(self, config):
        """Test that AuthenticateTool is not registered when disabled."""
        config.server.disabled_tools = ["AuthenticateTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "AuthenticateTool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_registration(self, config):
        """Test that GetAgentInfo is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentInfo" in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_disabled(self, config):
        """Test that GetAgentInfo is not registered when disabled."""
        config.server.disabled_tools = ["GetAgentInfo"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentInfo" not in tool_names

    @pytest.mark.asyncio
    async def test_run_vql_query_tool_registration(self, config):
        """Test that RunVQLQueryTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "RunVQLQueryTool" in tool_names

    @pytest.mark.asyncio
    async def test_run_vql_query_tool_disabled(self, config):
        """Test that RunVQLQueryTool is not registered when disabled."""
        config.server.disabled_tools = ["RunVQLQueryTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "RunVQLQueryTool" not in tool_names

    @pytest.mark.asyncio
    async def test_list_linux_artifacts_tool_registration(self, config):
        """Test that ListLinuxArtifactsTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListLinuxArtifactsTool" in tool_names

    @pytest.mark.asyncio
    async def test_list_linux_artifacts_tool_disabled(self, config):
        """Test that ListLinuxArtifactsTool is not registered when disabled."""
        config.server.disabled_tools = ["ListLinuxArtifactsTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListLinuxArtifactsTool" not in tool_names

    @pytest.mark.asyncio
    async def test_list_windows_artifacts_tool_registration(self, config):
        """Test that ListWindowsArtifactsTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListWindowsArtifactsTool" in tool_names

    @pytest.mark.asyncio
    async def test_list_windows_artifacts_tool_disabled(self, config):
        """Test that ListWindowsArtifactsTool is not registered when disabled."""
        config.server.disabled_tools = ["ListWindowsArtifactsTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListWindowsArtifactsTool" not in tool_names

    @pytest.mark.asyncio
    async def test_authenticate_tool_execution(self, config):
        """Test AuthenticateTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.authenticate = AsyncMock(
            return_value={"status": "authenticated", "user": "test_user"},
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        authenticate_tool = tools["AuthenticateTool"]

        # Execute the tool
        result = await authenticate_tool.run({"args": {}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        assert "Authentication successful" in result.content[0].text
        mock_client.authenticate.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_execution_success(self, config):
        """Test GetAgentInfo execution with successful result."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.find_client_info = Mock(
            return_value={
                "client_id": "C.1234567890",
                "hostname": "test-host",
                "os_info": {"system": "Linux", "release": "Ubuntu 20.04"},
            },
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_agent_info_tool = tools["GetAgentInfo"]

        # Execute the tool
        result = await get_agent_info_tool.run({"args": {"hostname": "test-host"}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        assert "Client information for 'test-host'" in result.content[0].text
        assert "C.1234567890" in result.content[0].text
        mock_client.find_client_info.assert_called_once_with("test-host")

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_execution_not_found(self, config):
        """Test GetAgentInfo execution when client not found."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.find_client_info = Mock(return_value=None)
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_agent_info_tool = tools["GetAgentInfo"]

        # Execute the tool
        result = await get_agent_info_tool.run({"args": {"hostname": "nonexistent-host"}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        assert "No client found with hostname: nonexistent-host" in result.content[0].text
        mock_client.find_client_info.assert_called_once_with("nonexistent-host")

    @pytest.mark.asyncio
    async def test_run_vql_query_tool_execution(self, config):
        """Test RunVQLQueryTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {"client_id": "C.1234567890", "hostname": "test-host"},
                {"client_id": "C.0987654321", "hostname": "test-host-2"},
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        run_vql_query_tool = tools["RunVQLQueryTool"]

        # Execute the tool
        result = await run_vql_query_tool.run({"args": {"vql": "SELECT * FROM clients() LIMIT 10"}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        # Tools return their text directly (no JSON-encoded wrapper).
        result_data = json.loads(result.content[0].text)
        assert len(result_data) == 2
        assert result_data[0]["client_id"] == "C.1234567890"
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT * FROM clients() LIMIT 10", max_rows=None, timeout=None
        )

    @pytest.mark.asyncio
    async def test_list_linux_artifacts_tool_execution(self, config):
        """Test ListLinuxArtifactsTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Linux.System.Info",
                    "description": "Gather basic system information from a Linux system. This includes OS version, kernel info, and hardware details.",
                    "parameters": [{"name": "param1"}, {"name": "param2"}],
                },
                {
                    "name": "Linux.Network.Netstat",
                    "description": "Parse netstat output to show network connections and listening ports.",
                    "parameters": [{"name": "connection_type"}],
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        list_linux_artifacts_tool = tools["ListLinuxArtifactsTool"]

        # Execute the tool
        result = await list_linux_artifacts_tool.run({"args": {}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        # Tools return their text directly (no JSON-encoded wrapper).
        response_data = json.loads(result.content[0].text)

        # Check that we have the expected artifacts
        assert len(response_data) == 2
        assert response_data[0]["name"] == "Linux.System.Info"
        assert "Gather basic system information" in response_data[0]["short_description"]
        assert response_data[0]["parameters"] == ["param1", "param2"]

        assert response_data[1]["name"] == "Linux.Network.Netstat"
        assert "Parse netstat output" in response_data[1]["short_description"]
        assert response_data[1]["parameters"] == ["connection_type"]

        # Verify the VQL query was called
        mock_client.run_vql_query.assert_called_once()
        called_vql = mock_client.run_vql_query.call_args[0][0]
        assert "artifact_definitions()" in called_vql
        assert "linux\\." in called_vql

    @pytest.mark.asyncio
    async def test_list_windows_artifacts_tool_execution(self, config):
        """Test ListWindowsArtifactsTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Windows.System.Services",
                    "description": "List all installed Windows services with their configuration and status. This includes service name, display name, and current state.",
                    "parameters": [{"name": "service_name"}, {"name": "status_filter"}],
                },
                {
                    "name": "Windows.Registry.NTUser",
                    "description": "Parse NTUSER.DAT registry hive files to extract user-specific registry keys.",
                    "parameters": [{"name": "key_path"}],
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        list_windows_artifacts_tool = tools["ListWindowsArtifactsTool"]

        # Execute the tool
        result = await list_windows_artifacts_tool.run({"args": {}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        # Tools return their text directly (no JSON-encoded wrapper).
        response_data = json.loads(result.content[0].text)

        # Check that we have the expected artifacts
        assert len(response_data) == 2
        assert response_data[0]["name"] == "Windows.System.Services"
        assert "List all installed Windows services" in response_data[0]["short_description"]
        assert response_data[0]["parameters"] == ["service_name", "status_filter"]

        assert response_data[1]["name"] == "Windows.Registry.NTUser"
        assert "Parse NTUSER" in response_data[1]["short_description"]
        assert response_data[1]["parameters"] == ["key_path"]

        # Verify the VQL query was called
        mock_client.run_vql_query.assert_called_once()
        called_vql = mock_client.run_vql_query.call_args[0][0]
        assert "artifact_definitions()" in called_vql
        assert "^windows\\." in called_vql

    @pytest.mark.asyncio
    async def test_collect_artifact_tool_registration(self, config):
        """Test CollectArtifactTool registration."""
        server = VelociraptorMCPServer(config)

        # Get all tools
        tools = await server.app.get_tools()

        # Check if CollectArtifactTool is registered
        assert "CollectArtifactTool" in tools
        tool = tools["CollectArtifactTool"]
        assert tool.name == "CollectArtifactTool"
        assert "collect" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_collect_artifact_tool_disabled(self, config):
        """Test CollectArtifactTool when disabled."""
        # Disable the tool
        config.server.disabled_tools = ["CollectArtifactTool"]
        server = VelociraptorMCPServer(config)

        # Get all tools
        tools = await server.app.get_tools()

        # Check if CollectArtifactTool is not registered
        assert "CollectArtifactTool" not in tools

    @pytest.mark.asyncio
    async def test_collect_artifact_tool_execution(self, config):
        """Test CollectArtifactTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.start_collection = Mock(
            return_value=[
                {
                    "flow_id": "F.1234567890ABCDEF",
                    "artifacts": ["Windows.System.Users"],
                    "status": "RUNNING",
                    "client_id": "C.1234567890",
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        collect_artifact_tool = tools["CollectArtifactTool"]

        # Execute the tool
        result = await collect_artifact_tool.run(
            {
                "args": {
                    "client_id": "C.1234567890",
                    "artifact": "Windows.System.Users",
                    "parameters": "user='Administrator'",
                },
            },
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Collection started successfully" in result_text
        assert "F.1234567890ABCDEF" in result_text
        assert "Windows.System.Users" in result_text

        # Verify the start_collection was called with correct parameters
        mock_client.start_collection.assert_called_once_with(
            "C.1234567890",
            "Windows.System.Users",
            "user='Administrator'",
        )

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_registration(self, config):
        """Test GetCollectionResultsTool registration."""
        server = VelociraptorMCPServer(config)

        # Get all tools
        tools = await server.app.get_tools()

        # Check if GetCollectionResultsTool is registered
        assert "GetCollectionResultsTool" in tools
        tool = tools["GetCollectionResultsTool"]
        assert tool.name == "GetCollectionResultsTool"
        assert (
            "retrieve" in tool.description.lower()
            or "collection results" in tool.description.lower()
        )

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_disabled(self, config):
        """Test GetCollectionResultsTool when disabled."""
        # Disable the tool
        config.server.disabled_tools = ["GetCollectionResultsTool"]
        server = VelociraptorMCPServer(config)

        # Get all tools
        tools = await server.app.get_tools()

        # Check if GetCollectionResultsTool is not registered
        assert "GetCollectionResultsTool" not in tools

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_execution_success(self, config):
        """Test GetCollectionResultsTool execution with successful results."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()

        # Mock run_vql_query for artifact details (no sources for this artifact)
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Windows.System.Users",
                    "source_names": [],  # No sources, so use artifact name directly
                },
            ],
        )

        mock_client.get_flow_status = Mock(return_value="FINISHED")
        mock_client.get_flow_results = Mock(
            return_value=[
                {
                    "username": "Administrator",
                    "full_name": "Built-in account for administering the computer/domain",
                    "uid": 500,
                    "gid": 513,
                },
                {
                    "username": "Guest",
                    "full_name": "Built-in account for guest access to the computer/domain",
                    "uid": 501,
                    "gid": 514,
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_collection_results_tool = tools["GetCollectionResultsTool"]

        # Execute the tool
        result = await get_collection_results_tool.run(
            {
                "args": {
                    "client_id": "C.1234567890",
                    "flow_id": "F.ABCDEF123456",
                    "artifact": "Windows.System.Users",
                    "fields": "username,full_name,uid,gid",
                    "max_retries": 1,  # Set to 1 for quick testing
                    "retry_delay": 1,  # Set to 1 second for quick testing
                },
            },
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Collection results for flow F.ABCDEF123456" in result_text
        assert "Administrator" in result_text
        assert "Guest" in result_text

        # Verify the methods were called correctly
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "Windows.System.Users"},
        )
        mock_client.get_flow_status.assert_called_once_with(
            "C.1234567890",
            "F.ABCDEF123456",
            "Windows.System.Users",
        )
        mock_client.get_flow_results.assert_called_once_with(
            "C.1234567890",
            "F.ABCDEF123456",
            "Windows.System.Users",
            "username,full_name,uid,gid",
        )

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_execution_timeout(self, config):
        """Test GetCollectionResultsTool execution when flow doesn't complete."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()

        # Mock run_vql_query for artifact details (no sources for this artifact)
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Windows.System.Users",
                    "source_names": [],  # No sources, so use artifact name directly
                },
            ],
        )

        mock_client.get_flow_status = Mock(return_value="RUNNING")  # Always running
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_collection_results_tool = tools["GetCollectionResultsTool"]

        # Execute the tool with quick timeout
        result = await get_collection_results_tool.run(
            {
                "args": {
                    "client_id": "C.1234567890",
                    "flow_id": "F.ABCDEF123456",
                    "artifact": "Windows.System.Users",
                    "max_retries": 2,  # Set to 2 for quick testing
                    "retry_delay": 1,  # Set to 1 second for quick testing
                },
            },
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Collection results not available after 2 retries" in result_text
        assert "F.ABCDEF123456" in result_text
        assert "may still be running" in result_text

        # Verify the methods were called correctly
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "Windows.System.Users"},
        )
        # Verify the status was checked multiple times
        assert mock_client.get_flow_status.call_count == 2

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_execution_multiple_sources(self, config):
        """Test GetCollectionResultsTool execution with an artifact that has multiple sources."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()

        # Mock run_vql_query for artifact details (artifact with multiple sources)
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Linux.Debian.Packages",
                    "source_names": ["DebPackages", "Snaps"],  # Multiple sources
                },
            ],
        )

        # Mock get_flow_status to return FINISHED for both sources
        mock_client.get_flow_status = Mock(return_value="FINISHED")

        # Mock get_flow_results to return different results for each source
        def mock_get_flow_results(client_id, flow_id, artifact, fields):
            if artifact == "Linux.Debian.Packages/DebPackages":
                return [
                    {"package": "vim", "version": "8.2.0716", "source": "deb"},
                    {"package": "curl", "version": "7.68.0", "source": "deb"},
                ]
            elif artifact == "Linux.Debian.Packages/Snaps":
                return [
                    {"package": "firefox", "version": "99.0", "source": "snap"},
                    {"package": "code", "version": "1.68.1", "source": "snap"},
                ]
            return []

        mock_client.get_flow_results = Mock(side_effect=mock_get_flow_results)
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_collection_results_tool = tools["GetCollectionResultsTool"]

        # Execute the tool
        result = await get_collection_results_tool.run(
            {
                "args": {
                    "client_id": "C.1234567890",
                    "flow_id": "F.ABCDEF123456",
                    "artifact": "Linux.Debian.Packages",
                    "fields": "*",
                    "max_retries": 1,
                    "retry_delay": 1,
                },
            },
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Collection results for flow F.ABCDEF123456" in result_text
        assert "Linux.Debian.Packages with multiple sources" in result_text
        assert "total_records" in result_text
        assert "DebPackages" in result_text
        assert "Snaps" in result_text

        # Verify the methods were called correctly
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "Linux.Debian.Packages"},
        )

        # Verify get_flow_status was called for both sources
        assert mock_client.get_flow_status.call_count == 2
        mock_client.get_flow_status.assert_any_call(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/DebPackages",
        )
        mock_client.get_flow_status.assert_any_call(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/Snaps",
        )

        # Verify get_flow_results was called for both sources
        assert mock_client.get_flow_results.call_count == 2
        mock_client.get_flow_results.assert_any_call(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/DebPackages",
            "*",
        )
        mock_client.get_flow_results.assert_any_call(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/Snaps",
            "*",
        )

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_execution_empty_sources(self, config):
        """Test GetCollectionResultsTool execution with artifact that has empty source names."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()

        # Mock run_vql_query for artifact details with empty/null sources
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Linux.Sys.Users",
                    "source_names": ["", None, "   "],  # Empty, null, and whitespace-only sources
                },
            ],
        )

        mock_client.get_flow_status = Mock(return_value="FINISHED")
        mock_client.get_flow_results = Mock(
            return_value=[
                {
                    "username": "root",
                    "uid": 0,
                    "gid": 0,
                },
                {
                    "username": "user1",
                    "uid": 1000,
                    "gid": 1000,
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_collection_results_tool = tools["GetCollectionResultsTool"]

        # Execute the tool
        result = await get_collection_results_tool.run(
            {
                "args": {
                    "client_id": "C.1234567890",
                    "flow_id": "F.ABCDEF123456",
                    "artifact": "Linux.Sys.Users",
                    "fields": "*",
                    "max_retries": 1,
                    "retry_delay": 1,
                },
            },
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Collection results for flow F.ABCDEF123456" in result_text
        assert "root" in result_text
        assert "user1" in result_text

        # Verify the methods were called correctly - should use artifact name directly without slash
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "Linux.Sys.Users"},
        )
        mock_client.get_flow_status.assert_called_once_with(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Sys.Users",  # Should NOT have a trailing slash
        )
        mock_client.get_flow_results.assert_called_once_with(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Sys.Users",  # Should NOT have a trailing slash
            "*",
        )

    @pytest.mark.asyncio
    async def test_collect_artifact_details_tool_registration(self, config):
        """Test CollectArtifactDetailsTool registration."""
        server = VelociraptorMCPServer(config)

        # Get all tools
        tools = await server.app.get_tools()

        # Check if CollectArtifactDetailsTool is registered
        assert "CollectArtifactDetailsTool" in tools
        tool = tools["CollectArtifactDetailsTool"]
        assert tool.name == "CollectArtifactDetailsTool"
        assert "detailed information" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_collect_artifact_details_tool_disabled(self, config):
        """Test CollectArtifactDetailsTool when disabled."""
        # Disable the tool
        config.server.disabled_tools = ["CollectArtifactDetailsTool"]
        server = VelociraptorMCPServer(config)

        # Get all tools
        tools = await server.app.get_tools()

        # Check if CollectArtifactDetailsTool is not registered
        assert "CollectArtifactDetailsTool" not in tools

    @pytest.mark.asyncio
    async def test_collect_artifact_details_tool_execution_success(self, config):
        """Test CollectArtifactDetailsTool execution with successful result."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Windows.System.Users",
                    "description": "Collect user account information from Windows systems including user profiles, group memberships, and account settings.",
                    "parameters": [
                        {"name": "UserFilter", "description": "Filter users by name pattern"},
                        {"name": "IncludeGroups", "description": "Include group memberships"},
                    ],
                    "source_names": ["Users", "Groups"],  # List of source names
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        collect_artifact_details_tool = tools["CollectArtifactDetailsTool"]

        # Execute the tool
        result = await collect_artifact_details_tool.run(
            {"args": {"artifact_name": "Windows.System.Users"}},
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Artifact details for 'Windows.System.Users'" in result_text
        assert "Windows.System.Users" in result_text
        assert "Collect user account information" in result_text
        assert "UserFilter" in result_text
        assert "IncludeGroups" in result_text
        assert "source_names" in result_text
        assert "source_count" in result_text

        # Verify the VQL query was called with correct parameters
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,description,parameters,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "Windows.System.Users"},
        )

    @pytest.mark.asyncio
    async def test_collect_artifact_details_tool_execution_not_found(self, config):
        """Test CollectArtifactDetailsTool execution when artifact not found."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(return_value=[])  # Empty result
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        collect_artifact_details_tool = tools["CollectArtifactDetailsTool"]

        # Execute the tool
        result = await collect_artifact_details_tool.run(
            {"args": {"artifact_name": "NonExistent.Artifact"}},
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "No artifact found with name: NonExistent.Artifact" in result_text

        # Verify the VQL query was called
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,description,parameters,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "NonExistent.Artifact"},
        )

    @pytest.mark.asyncio
    async def test_get_collection_results_tool_execution_partial_results(self, config):
        """Test GetCollectionResultsTool execution with partial results when some sources timeout."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()

        # Mock run_vql_query for artifact details with multiple sources
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Linux.Debian.Packages",
                    "source_names": ["DebPackages", "Snaps"],  # Multiple sources
                },
            ],
        )

        # Mock get_flow_status to simulate one source finishing and one still running
        def mock_get_flow_status(client_id, flow_id, artifact_name):
            if "DebPackages" in artifact_name:
                return "FINISHED"  # DebPackages source finishes
            elif "Snaps" in artifact_name:
                return "RUNNING"  # Snaps source keeps running
            return "RUNNING"

        mock_client.get_flow_status = Mock(side_effect=mock_get_flow_status)

        # Mock get_flow_results to return data for the finished source
        def mock_get_flow_results(client_id, flow_id, artifact_name, fields):
            if "DebPackages" in artifact_name:
                return [
                    {"package": "vim", "version": "8.2", "architecture": "amd64"},
                    {"package": "curl", "version": "7.68", "architecture": "amd64"},
                ]
            return []

        mock_client.get_flow_results = Mock(side_effect=mock_get_flow_results)
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_collection_results_tool = tools["GetCollectionResultsTool"]

        # Execute the tool with low retry count to trigger partial results
        result = await get_collection_results_tool.run(
            {
                "args": {
                    "client_id": "C.1234567890",
                    "flow_id": "F.ABCDEF123456",
                    "artifact": "Linux.Debian.Packages",
                    "fields": "*",
                    "max_retries": 1,  # Low retry count to trigger timeout
                    "retry_delay": 1,
                },
            },
        )

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")

        result_text = result.content[0].text
        assert "Collection results for flow F.ABCDEF123456" in result_text
        assert "with partial results" in result_text
        assert "WARNING: Partial results returned after timeout" in result_text
        assert "Completed 1/2 sources" in result_text
        assert "Incomplete sources: Linux.Debian.Packages/Snaps" in result_text
        assert "DebPackages" in result_text  # Should have results from finished source
        assert "vim" in result_text  # Verify actual data is included
        assert "curl" in result_text

        # Verify the methods were called correctly
        mock_client.run_vql_query.assert_called_once_with(
            "SELECT name,sources.name as source_names FROM artifact_definitions() WHERE name = McpArtifactName",
            env={"McpArtifactName": "Linux.Debian.Packages"},
        )

        # Verify get_flow_status was called for both sources
        assert (
            mock_client.get_flow_status.call_count >= 2
        )  # Called at least twice (once per source)
        mock_client.get_flow_status.assert_any_call(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/DebPackages",
        )
        mock_client.get_flow_status.assert_any_call(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/Snaps",
        )

        # Verify get_flow_results was called only for the finished source
        mock_client.get_flow_results.assert_called_once_with(
            "C.1234567890",
            "F.ABCDEF123456",
            "Linux.Debian.Packages/DebPackages",
            "*",
        )
