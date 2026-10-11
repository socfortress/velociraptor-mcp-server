"""Tests for MCP-1/2/3/4: HTTP transport, bearer auth, read-only gating, row caps and VQL parameterisation."""

import asyncio
import json
from unittest.mock import Mock

import httpx
import pytest

from velociraptor_mcp_server.client import VelociraptorClient, parse_parameters
from velociraptor_mcp_server.config import ServerConfig
from velociraptor_mcp_server.server import TOOL_META, VelociraptorMCPServer


def make_server(config, **server_overrides):
    for key, value in server_overrides.items():
        setattr(config.server, key, value)
    return VelociraptorMCPServer(config)


def tool_names(server):
    return set(asyncio.run(server.app.get_tools()))


def response(rows):
    r = Mock()
    r.Response = json.dumps(rows)
    r.error = None
    return r


@pytest.fixture
def stubbed(velociraptor_client, mock_grpc_client):
    velociraptor_client.stub = mock_grpc_client
    mock_grpc_client.Query.return_value = [response([{"a": 1}])]
    return velociraptor_client, mock_grpc_client


def sent(mock_grpc_client):
    request = mock_grpc_client.Query.call_args.args[0]
    return request, {e.key: e.value for e in request.env}


# --- MCP-3: read-only gating ------------------------------------------------------------------------


def test_every_tool_is_classified(config):
    assert tool_names(make_server(config)) == set(TOOL_META)


def test_read_only_drops_vql_and_collection(config):
    names = tool_names(make_server(config, read_only=True))
    assert "RunVQLQueryTool" not in names and "CollectArtifactTool" not in names
    assert {"GetAgentInfo", "GetCollectionResultsTool", "CollectArtifactDetailsTool"} <= names


def test_unclassified_tool_counts_as_write(config):
    assert make_server(config, read_only=True)._enabled("SomeFutureTool") is False


def test_disabled_categories(config):
    names = tool_names(make_server(config, disabled_categories=["artifacts"]))
    assert not any(n.startswith("List") for n in names) and "GetAgentInfo" in names


# --- MCP-1/2: transport and auth --------------------------------------------------------------------


def test_http_requires_token(config):
    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN"):
        make_server(config, auth_token="").http_app()


@pytest.mark.asyncio
async def test_http_auth_and_health(config):
    app = make_server(config, auth_token="s3cret").http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        assert (await client.get("/healthz")).json() == {"status": "ok"}
        assert (await client.post("/mcp", json={})).status_code == 401
        assert (await client.post("/mcp", json={}, headers={"Authorization": "Bearer x"})).status_code == 401


def test_env_config(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "tok")
    monkeypatch.setenv("MCP_SERVER_PORT", "9002")
    cfg = ServerConfig.from_env()
    assert (cfg.transport, cfg.auth_token, cfg.port) == ("http", "tok", 9002)


# --- MCP-4: row caps, timeouts, parameterised VQL ---------------------------------------------------


def test_max_rows_and_timeout_are_sent_and_capped(stubbed):
    client, grpc_stub = stubbed
    client.config.max_rows, client.config.timeout = 50, 30
    grpc_stub.Query.return_value = [response([{"n": i} for i in range(40)]), response([{"n": i} for i in range(40)])]
    rows = client.run_vql_query("SELECT * FROM clients()", max_rows=500, timeout=600)
    request, _ = sent(grpc_stub)
    assert (request.max_row, request.timeout) == (50, 30)  # never above the configured caps
    assert len(rows) == 50
    assert grpc_stub.Query.call_args.kwargs["timeout"] == 35


def test_caller_can_lower_the_caps(stubbed):
    client, grpc_stub = stubbed
    client.run_vql_query("SELECT * FROM info()", max_rows=5, timeout=10)
    request, _ = sent(grpc_stub)
    assert (request.max_row, request.timeout) == (5, 10)


def test_hostname_is_a_variable_not_vql(stubbed):
    client, grpc_stub = stubbed
    evil = "x' OR 1=1 OR os_info.hostname =~ '"
    client.find_client_info(evil)
    request, env = sent(grpc_stub)
    assert evil not in request.Query[0].VQL and env == {"McpHostname": evil}


def test_flow_results_parameterised_and_validated(stubbed):
    client, grpc_stub = stubbed
    client.get_flow_results("C.abc123", "F.ABC123", "Windows.System.Users", "Name, Uid")
    request, env = sent(grpc_stub)
    assert "SELECT Name, Uid FROM source(client_id=McpClientId" in request.Query[0].VQL
    assert env == {"McpClientId": "C.abc123", "McpFlowId": "F.ABC123", "McpArtifact": "Windows.System.Users"}
    for bad in [
        ("C.abc123", "F.ABC123", "Windows.System.Users", "* FROM info() --"),
        ("C.abc'", "F.ABC123", "Windows.System.Users", "*"),
        ("C.abc123", "F.1') OR (1", "Windows.System.Users", "*"),
        ("C.abc123", "F.ABC123", "Windows.System.Users') LET x <= 1 --", "*"),
    ]:
        with pytest.raises(ValueError):
            client.get_flow_results(*bad)


def test_flow_status_regex_is_escaped(stubbed):
    client, grpc_stub = stubbed
    client.get_flow_status("C.abc123", "F.ABC123", "Windows.System.Users/Users")
    _, env = sent(grpc_stub)
    assert env["McpDonePattern"] == r"^Collection Windows\.System\.Users/Users is done after"


def test_collection_parameters_parsed_strictly(stubbed):
    client, grpc_stub = stubbed
    client.start_collection("C.abc123", "Windows.System.Users", "a='1', b='two words'")
    request, env = sent(grpc_stub)
    assert json.loads(env["McpParams"]) == {"a": "1", "b": "two words"}
    assert "parse_json(data=McpParams)" in request.Query[0].VQL
    with pytest.raises(ValueError):
        parse_parameters("a='1'), x=dict(y='2'")
    with pytest.raises(ValueError):
        parse_parameters("a=1")
    assert parse_parameters("") == {}


def test_artifact_lookup_tools_parameterised(config):
    server = make_server(config)
    mock_client = Mock()
    mock_client.stub = Mock()
    mock_client.run_vql_query = Mock(return_value=[])
    server._client = mock_client
    tools = asyncio.run(server.app.get_tools())
    asyncio.run(tools["FindArtifactDetailsTool"].run({"args": {"artifact_name": "X' OR 1=1"}}))
    vql, kwargs = mock_client.run_vql_query.call_args.args[0], mock_client.run_vql_query.call_args.kwargs
    assert "X' OR" not in vql and kwargs["env"] == {"McpArtifactName": "X' OR 1=1"}


def test_grpc_runs_off_the_event_loop(config):
    """Blocking gRPC calls run in a worker thread, so they don't stall other requests."""
    import threading

    server = make_server(config)
    seen = {}

    def fake_query(vql, **kwargs):
        seen["thread"] = threading.current_thread()
        return [{"name": "Linux.Sys.Users"}]

    mock_client = Mock()
    mock_client.stub = Mock()
    mock_client.run_vql_query = fake_query
    server._client = mock_client
    tools = asyncio.run(server.app.get_tools())
    asyncio.run(tools["ListLinuxArtifactNamesTool"].run({"args": {}}))
    assert seen["thread"] is not threading.main_thread()


def test_query_variables_never_shadow_columns(stubbed):
    """A variable named like a column alias (e.g. Hostname) is shadowed by the row and matches everything."""
    client, grpc_stub = stubbed
    client.find_client_info("windows-demo")
    request, env = sent(grpc_stub)
    assert list(env) == ["McpHostname"] and "= McpHostname" in request.Query[0].VQL


def test_hunt_flow_ids_accepted(stubbed):
    client, grpc_stub = stubbed
    client.get_flow_results("C.abc123", "F.D2MSOOHV9UR3S.H", "Linux.Sys.Users")
    _, env = sent(grpc_stub)
    assert env["McpFlowId"] == "F.D2MSOOHV9UR3S.H"
