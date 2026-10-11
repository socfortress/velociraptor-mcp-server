# Velociraptor MCP Server

A production-ready **Model Context Protocol (MCP) server** for seamless integration between Velociraptor DFIR and Large Language Models (LLMs).

[![Build Status](https://github.com/socfortress/velociraptor-mcp-server/actions/workflows/publish.yml/badge.svg)](https://github.com/socfortress/velociraptor-mcp-server/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UC4EUQtTxeC8wGrKRafI6pZg)](https://www.youtube.com/@taylorwalton_socfortress/videos)
[![Get in Touch](https://img.shields.io/badge/📧%20Get%20in%20Touch-Friendly%20Support%20Awaits!-blue?style=for-the-badge)](https://www.socfortress.co/contact_form.html)

> **Why?**
> Combine the power of Velociraptor's comprehensive digital forensics and incident response capabilities with the reasoning capabilities of large language models—enabling natural language queries and intelligent analysis of your forensic data.

---

## ✨ Key Features

- 🚀 **Production-ready**: Proper package structure, logging, error handling, and configuration management
- 🔐 **Secure**: JWT token management with automatic refresh
- 🌐 **HTTP/2 Support**: Built on modern async HTTP client with connection pooling
- 📊 **Comprehensive API**: Access Velociraptor artifacts, hunts, collections, and more
- 🎛️ **Configurable**: Environment variables, CLI arguments, and fine-grained tool filtering
- 📦 **Pip installable**: Install directly from GitHub releases or source

---

## Table of Contents
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Available Tools](#available-tools)
- [Development](#development)
- [CI/CD](#continuous-integration)
- [Deployment](#deployment)
- [Security](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

### 1. Install

#### From GitHub (Recommended)
```bash
python -m venv .venv && source .venv/bin/activate
pip install git+https://github.com/socfortress/velociraptor-mcp-server.git
```

#### From Release Artifacts
1. Go to the [Releases page](https://github.com/socfortress/velociraptor-mcp-server/releases)
2. Download the latest `.whl` file
3. Install with:
```bash
pip install velociraptor_mcp_server-*.whl
```

#### From Build Artifacts (Latest Build)
1. Go to the [Actions tab](https://github.com/socfortress/velociraptor-mcp-server/actions)
2. Click on the latest successful workflow run
3. Download the `python-package-distributions` artifact
4. Extract and install:
```bash
pip install velociraptor_mcp_server-*.whl
```

### 2. Configure Environment

Create a `.env` file in your project directory:

```env
# Velociraptor Server Configuration
VELOCIRAPTOR_API_KEY=/path/to/api.config.yaml
VELOCIRAPTOR_SSL_VERIFY=false
VELOCIRAPTOR_TIMEOUT=30

# MCP Server Configuration
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8000

# Logging Configuration
LOG_LEVEL=INFO

# Tool Filtering (optional)
# VELOCIRAPTOR_DISABLED_TOOLS=CollectArtifactTool,RunVQLQueryTool
```

**Note**: For `VELOCIRAPTOR_API_KEY`, provide the full path to your Velociraptor `api.config.yaml` file. You can generate this file from your Velociraptor server using the admin interface or CLI.

### 3. Run the Server

```bash
# Using the CLI command
velociraptor-mcp-server

# Or using the Python module
python -m velociraptor_mcp_server

# Streamable HTTP for networked clients (requires MCP_AUTH_TOKEN)
MCP_AUTH_TOKEN=$(openssl rand -hex 32) velociraptor-mcp-server --transport http --host 0.0.0.0 --port 8000
```

By default the server speaks MCP over **stdio**, for clients that launch it as a subprocess (`.mcp.json`).
With `--transport http` (or `MCP_TRANSPORT=http`) it serves streamable HTTP at `http://<host>:<port>/mcp`:

- Every request must carry `Authorization: Bearer <MCP_AUTH_TOKEN>`. The server refuses to start in HTTP mode without a token.
- `GET /healthz` is unauthenticated, for container health checks.

For an AI analyst that should only read existing results, set `VELOCIRAPTOR_READ_ONLY=true`. `RunVQLQueryTool` (arbitrary VQL) and `CollectArtifactTool` are then not registered.

Example from Pydantic AI:

```python
from pydantic_ai.mcp import MCPToolset

velo = MCPToolset("http://velociraptor-mcp:8000/mcp", id="velociraptor", headers={"Authorization": f"Bearer {token}"})
async with velo:
    info = await velo.direct_call_tool("GetAgentInfo", {"args": {"hostname": "workstation-01"}})
```

---

## Installation

### Requirements

- Python 3.11 or higher
- Access to a Velociraptor server instance
- Network connectivity to your Velociraptor server
- Velociraptor API configuration file (api.config.yaml)

### Development Installation

```bash
git clone https://github.com/socfortress/velociraptor-mcp-server.git
cd velociraptor-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

---

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VELOCIRAPTOR_API_KEY` | Path to Velociraptor API config file (api.config.yaml) | None | ✅ |
| `VELOCIRAPTOR_SSL_VERIFY` | SSL verification | `true` | ❌ |
| `VELOCIRAPTOR_TIMEOUT` | Query timeout (seconds); the upper bound for any query, including `RunVQLQueryTool`'s `timeout` | `30` | ❌ |
| `VELOCIRAPTOR_MAX_ROWS` | Row cap for any query, including `RunVQLQueryTool`'s `max_rows` | `1000` | ❌ |
| `VELOCIRAPTOR_READ_ONLY` | Don't register `RunVQLQueryTool` or `CollectArtifactTool`. Unclassified tools count as writes. | `false` | ❌ |
| `VELOCIRAPTOR_DISABLED_CATEGORIES` | Comma-separated categories: `auth`, `clients`, `vql`, `artifacts`, `collections`, `hunts` | None | ❌ |
| `MCP_TRANSPORT` | `stdio` or `http` | `stdio` | ❌ |
| `MCP_SERVER_HOST` | HTTP bind host | `127.0.0.1` | ❌ |
| `MCP_SERVER_PORT` | HTTP port | `8000` | ❌ |
| `MCP_AUTH_TOKEN` | Bearer token for the HTTP transport | None | ✅ for `http` |
| `LOG_LEVEL` | Logging level | `INFO` | ❌ |
| `VELOCIRAPTOR_DISABLED_TOOLS` | Comma-separated list of disabled tools | None | ❌ |

Untrusted values (hostnames, client and flow IDs, artifact names, collection parameters) are passed to Velociraptor as query variables, never spliced into VQL text. Field lists are validated as identifiers.

### CLI Options

```bash
velociraptor-mcp-server --help
```

Available options:
- `--transport`: `stdio` or `http` (default: `MCP_TRANSPORT`, else stdio)
- `--host`: HTTP bind host (default: `MCP_SERVER_HOST`, else 127.0.0.1)
- `--port`: HTTP port (default: `MCP_SERVER_PORT`, else 8000)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--api-config`: Path to Velociraptor API config file (overrides env var)
- `--no-ssl-verify`: Disable SSL certificate verification

---

## Usage

### Basic Usage

```python
from velociraptor_mcp_server import Config, create_server

# Create server with environment configuration
config = Config.from_env()
server = create_server(config)

# Start the server
server.start()
```

### Custom Configuration

```python
from velociraptor_mcp_server.config import VelociraptorConfig, ServerConfig, Config

# Create custom configuration
velociraptor_config = VelociraptorConfig(
    api_key="/path/to/api.config.yaml",
    ssl_verify=False,
    timeout=60
)

server_config = ServerConfig(
    host="0.0.0.0",
    port=8080,
    log_level="DEBUG"
)

config = Config(velociraptor=velociraptor_config, server=server_config)
server = create_server(config)
```

### Integration with LangChain

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent

# Initialize LLM
model = ChatOpenAI(model="gpt-4")

# Connect to Velociraptor MCP server
client = MultiServerMCPClient({
    "velociraptor-mcp-server": {
        "transport": "sse",
        "url": "http://127.0.0.1:8000/sse/",
    }
})

# Get tools and create agent
tools = await client.get_tools()
agent = initialize_agent(
    tools=tools,
    llm=model,
    agent=AgentType.OPENAI_FUNCTIONS,
    verbose=True
)

# Query your Velociraptor data
response = await agent.ainvoke({
    "input": "Show me all active Velociraptor clients and their OS information"
})

# Collect artifacts from a specific client
artifact_response = await agent.ainvoke({
    "input": "Collect Windows.System.Users artifact from client workstation-01"
})

# Get artifact collection results
results_response = await agent.ainvoke({
    "input": "Get the results from flow F.ABC123 for Windows.System.Users artifact"
})
```

---

## Available Tools

The server exposes the following MCP tools for Velociraptor integration:

### 1. AuthenticateTool
- **Purpose**: Initialize and test connection to Velociraptor server
- **Parameters**: None
- **Usage**: Establishes a gRPC connection using the api.config.yaml file and tests authentication
- **Example**:
  ```json
  {"args": {}}
  ```

### 2. GetAgentInfo
- **Purpose**: Retrieve detailed information about a Velociraptor client by hostname/FQDN or client ID
- **Parameters** (give exactly one):
  - `hostname`: Hostname or FQDN of the client (exact match)
  - `client_id`: Velociraptor client ID, e.g. `C.1234abcd`
- **Usage**: Searches for a client and returns comprehensive details including client ID, OS information, agent version, and connection status
- **Example**:
  ```json
  {"args": {"hostname": "workstation-01"}}
  {"args": {"hostname": "server.domain.com"}}
  {"args": {"client_id": "C.194759cdaf0153c8"}}
  ```

### 3. RunVQLQueryTool
- **Purpose**: Execute VQL (Velociraptor Query Language) queries on the Velociraptor server
- **Parameters**:
  - `vql` (required): VQL query string to execute
  - `max_rows` (optional): Maximum number of rows to return
  - `timeout` (optional): Query timeout in seconds
- **Usage**: Allows custom VQL queries to retrieve information about clients, artifacts, hunts, flows, and more
- **Examples**:
  ```json
  {"args": {"vql": "SELECT client_id, os_info.hostname FROM clients() LIMIT 10"}}
  {"args": {"vql": "SELECT * FROM flows() WHERE client_id = 'C.1234567890'"}}
  {"args": {"vql": "SELECT name, description FROM artifacts() WHERE name =~ 'Windows'"}}
  ```

### 4. ListLinuxArtifactsTool
- **Purpose**: List available Linux artifacts in Velociraptor
- **Parameters**: None
- **Usage**: Returns a summary of all Linux client artifacts including names, descriptions, and required parameters
- **Example**:
  ```json
  {"args": {}}
  ```

### 5. ListWindowsArtifactsTool
- **Purpose**: List available Windows artifacts in Velociraptor
- **Parameters**: None
- **Usage**: Returns a summary of all Windows client artifacts including names, descriptions, and required parameters. Includes performance notes for NTFS queries (MFT, USN) and path filtering recommendations.
- **Example**:
  ```json
  {"args": {}}
  ```

### 6. CollectArtifactTool
- **Purpose**: Collect a Velociraptor artifact from a client
- **Parameters**:
  - `client_id` (required): Velociraptor client ID to target for collection
  - `artifact` (required): Name of the Velociraptor artifact to collect
  - `parameters` (optional): Comma-separated string of key='value' pairs to pass to the artifact
- **Usage**: Initiates artifact collection on a target client and returns a flow_id for tracking
- **Examples**:
  ```json
  {"args": {"client_id": "C.1234567890", "artifact": "Windows.System.Users"}}
  {"args": {"client_id": "C.0987654321", "artifact": "Linux.System.Uptime", "parameters": "format='seconds'"}}
  ```

### 7. GetCollectionResultsTool
- **Purpose**: Retrieve Velociraptor collection results for a given client, flow ID, and artifact
- **Parameters**:
  - `client_id` (required): Velociraptor client ID where the collection was run
  - `flow_id` (required): Flow ID returned from the initial collection
  - `artifact` (required): Name of the artifact collected (e.g., Windows.NTFS.MFT)
  - `fields` (optional): Comma-separated string of fields to return (default: '*')
  - `max_retries` (optional): Number of times to retry if the flow hasn't finished (default: 5)
  - `retry_delay` (optional): Time in seconds to wait between retries (default: 5)
  - `wait` (optional): `false` checks once and returns at once; use it for existing collections (default: `true`)
  - `limit` (optional): Maximum rows per artifact source, capped by `VELOCIRAPTOR_MAX_ROWS`
- **Usage**: Waits and retries if the flow hasn't finished or if no results are immediately available. Supports partial results for multi-source artifacts. Completion is read from the flow's own state first, so hunt flows (`F.….H`) are recognised as finished.
- **Features**:
  - **Multi-source support**: Handles artifacts with multiple sources (e.g., Linux.Debian.Packages with DebPackages/Snaps)
  - **Partial results**: Returns completed sources even if others are still running
  - **Intelligent retry**: Automatically waits for collection completion
- **Examples**:
  ```json
  {"args": {"client_id": "C.1234567890", "flow_id": "F.ABC123", "artifact": "Windows.System.Users"}}
  {"args": {"client_id": "C.0987654321", "flow_id": "F.DEF456", "artifact": "Linux.System.Uptime", "fields": "Uptime,BootTime"}}
  {"args": {"client_id": "C.1234567890", "flow_id": "F.ABC123", "artifact": "Windows.System.Users", "wait": false, "limit": 50}}
  ```

### 8. CollectArtifactDetailsTool
- **Purpose**: Get detailed information about a specific Velociraptor artifact
- **Parameters**:
  - `artifact_name` (required): Name of the artifact to get details for
- **Usage**: Retrieves comprehensive details including description, parameters, source code/VQL, parameter types, and default values. Useful for understanding artifacts before collection or debugging issues.
- **Examples**:
  ```json
  {"args": {"artifact_name": "Windows.System.Users"}}
  {"args": {"artifact_name": "Linux.Network.Netstat"}}
  {"args": {"artifact_name": "Windows.NTFS.MFT"}}
  ```

### 9. ListLinuxArtifactNamesTool
- **Purpose**: List only the names of available Linux artifacts in Velociraptor
- **Parameters**: None
- **Usage**: Returns a simple list of artifact names for Linux client artifacts
- **Example**:
  ```json
  {"args": {}}
  ```

### 10. ListWindowsArtifactNamesTool
- **Purpose**: List only the names of available Windows artifacts in Velociraptor
- **Parameters**: None
- **Usage**: Returns a simple list of artifact names for Windows client artifacts
- **Example**:
  ```json
  {"args": {}}
  ```

### 11. FindArtifactDetailsTool
- **Purpose**: Find a Velociraptor artifact's name, description, and parameters by artifact name
- **Parameters**:
  - `artifact_name` (required): Name of the artifact to get details for
- **Usage**: Returns a summary for the specified artifact, including its name, description, and parameter list
- **Example**:
  ```json
  {"args": {"artifact_name": "Windows.RemoteDesktop.RDPConnections"}}
  ```

### 12. ListHuntsTool
- **Purpose**: List hunts, newest first, with hunt ID, state, artifacts and client counts (read-only)
- **Parameters**: `limit` (optional, default 20)
- **Example**: `{"args": {"limit": 10}}`

### 13. GetHuntResultsTool
- **Purpose**: Read the existing results of a hunt for one artifact (read-only; runs nothing on endpoints)
- **Parameters**:
  - `hunt_id` (required): e.g. `H.D8CNRTTL5AOMM`
  - `artifact` (required): Artifact name. Artifacts with several sources must be given as `Artifact/Source`.
  - `fields` (optional): Comma-separated fields (default `*`)
  - `limit` (optional): Maximum rows, capped by `VELOCIRAPTOR_MAX_ROWS`
- **Example**:
  ```json
  {"args": {"hunt_id": "H.D30PRBIDUCKO0", "artifact": "Linux.Execute.RemoteBashScript/ScriptExecution", "fields": "FlowId, Status", "limit": 20}}
  ```

### Artifact Collection Workflow

The tools work together to provide a complete artifact collection workflow:

1. **Discovery**: Use `ListLinuxArtifactsTool` or `ListWindowsArtifactsTool` to explore available artifacts
2. **Investigation**: Use `CollectArtifactDetailsTool` to understand artifact parameters and requirements
3. **Client Identification**: Use `GetAgentInfo` to find the target client by hostname
4. **Collection**: Use `CollectArtifactTool` to start artifact collection and get a flow_id
5. **Results**: Use `GetCollectionResultsTool` to monitor progress and retrieve results
6. **Custom Queries**: Use `RunVQLQueryTool` for advanced custom investigations

---

## Development

### Setting up Development Environment

```bash
git clone https://github.com/socfortress/velociraptor-mcp-server.git
cd velociraptor-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=velociraptor_mcp_server

# Run specific test file
pytest tests/test_client.py

# Run with verbose output
pytest -v
```

### Building the Package

```bash
# Install build dependencies
pip install build twine

# Build the package
python -m build

# Check the package
twine check dist/*

# Test installation
pip install dist/*.whl
```

---

## Continuous Integration

This project uses GitHub Actions for automated building and testing:

- **Automatic builds**: Every push to `main` and `develop` branches triggers a build
- **Quality assurance**: Comprehensive testing including linting, type checking, and unit tests
- **Artifact publishing**: Built packages are available as GitHub releases and workflow artifacts

### Creating a Release

1. Create and push a git tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. The GitHub Action will automatically:
   - Build the package
   - Run all tests
   - Create a GitHub release with downloadable artifacts

### Installing from CI Artifacts

Visit the [Actions page](https://github.com/socfortress/velociraptor-mcp-server/actions) and download the `python-package-distributions` artifact from any successful build.

---

## Security Considerations

### Credentials Management
- **Never commit credentials**: Use environment variables or secrets management
- **Secure API config**: Protect your Velociraptor API configuration file (api.config.yaml)
- **Certificate security**: Ensure proper handling of client certificates and private keys

### Network Security
- **TLS/SSL**: Always use SSL/TLS for gRPC connections (`VELOCIRAPTOR_SSL_VERIFY=true`)
- **Firewall rules**: Restrict access to necessary ports only
- **VPN/Private networks**: Deploy in secured network environments

### Access Control
- **Least privilege**: Use Velociraptor API keys with minimal required permissions
- **Tool filtering**: Disable unnecessary tools using `VELOCIRAPTOR_DISABLED_TOOLS`
- **Client access**: Restrict which clients can be accessed through the API

### Monitoring
- **Logging**: Enable appropriate log levels for monitoring
- **Health checks**: Implement monitoring of the MCP server endpoint
- **Rate limiting**: Consider implementing rate limiting for production deployments

---

## Project Structure

```
velociraptor-mcp-server/
├── velociraptor_mcp_server/          # Main package
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # CLI entry point
│   ├── client.py             # Velociraptor API client
│   ├── config.py             # Configuration management
│   ├── server.py             # MCP server implementation
│   └── exceptions.py         # Custom exceptions
├── tests/                    # Test suite
│   ├── conftest.py          # Test configuration
│   ├── test_client.py       # Client tests
│   ├── test_config.py       # Configuration tests
│   └── test_server.py       # Server tests
├── .github/workflows/        # GitHub Actions
│   └── publish.yml          # CI/CD pipeline
├── requirements.txt          # Dependencies
├── pyproject.toml           # Package configuration
├── .env.example             # Environment template
├── Dockerfile               # Docker configuration
└── README.md                # This file
```

---

## Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes and add tests
4. **Ensure** tests pass: `pytest`
5. **Check** code quality: `black .`, `isort .`, `flake8 .`
6. **Commit** your changes (`git commit -m 'Add amazing feature'`)
7. **Push** to your branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

### Development Guidelines

- Write tests for new functionality
- Follow existing code style and patterns
- Update documentation for new features
- Ensure all CI checks pass

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Changelog

### v0.1.0 (Latest)
- Initial release
- Basic MCP server functionality
- Velociraptor API integration with gRPC authentication
- Complete artifact collection workflow
- CLI interface with configuration options
- Comprehensive test suite
- GitHub Actions CI/CD pipeline
- Support for multi-source artifacts with partial results

---

## Support

- 📖 [Documentation](https://github.com/socfortress/velociraptor-mcp-server#readme)
- 🐛 [Issues](https://github.com/socfortress/velociraptor-mcp-server/issues)
- 🏢 [SOCFortress](https://socfortress.co)

---

**Made with ❤️ by SOCFortress**
