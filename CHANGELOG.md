# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Container images are published to
`ghcr.io/socfortress/velociraptor-mcp-server` with matching tags.

## [0.2.0] - Unreleased

### Added
- Streamable HTTP transport (`--transport http` / `MCP_TRANSPORT`) at `/mcp`, with bearer-token
  auth (`MCP_AUTH_TOKEN`) and an unauthenticated `GET /healthz`.
- `TOOL_META` classification. `VELOCIRAPTOR_READ_ONLY` drops `RunVQLQueryTool` and
  `CollectArtifactTool`, and `VELOCIRAPTOR_DISABLED_CATEGORIES` is enforced.
- `VELOCIRAPTOR_MAX_ROWS` and `VELOCIRAPTOR_TIMEOUT` caps on every query. `RunVQLQueryTool` honours
  `max_rows`/`timeout`.
- `GetAgentInfo` by `client_id`. `GetCollectionResultsTool` gains `wait=false` and `limit`. New
  read-only `ListHuntsTool` and `GetHuntResultsTool`.
- `MCP_MAX_OUTPUT_CHARS` (default 32000) bounds tool output.
- Dockerfile (non-root, health check; mount the API config at `/config/api.config.yaml`) and a
  workflow that publishes images to GHCR (`main`, `sha-…`, and semver tags from `v*` git tags).

### Changed
- Untrusted values are passed as VQL query variables instead of being interpolated into VQL.
- Blocking gRPC calls run off the event loop.
- Tool output is compact JSON. Row results that exceed the limit drop whole rows and end with
  "[truncated: showing N of M rows (X characters)]". Text truncation says "showing N of M characters".
- Tools return their text directly. Before, the `[{"type": "text", ...}]` wrapper was JSON-encoded a
  second time, which doubled the escaping in every response.
- Backend failures and bad arguments are returned as MCP tool errors (`isError`) instead of success
  text. "Not found" answers stay as normal results.
- `fastmcp` is pinned to `>=2.10,<3`, `uvicorn` is declared, and Python 3.10+ is required.

### Fixed
- Flow status reads the flow's own state, so hunt flows (`F.….H`) are reported finished.

## [0.1.0]

- Initial stdio MCP server for Velociraptor.
