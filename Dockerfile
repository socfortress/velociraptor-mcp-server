# Velociraptor MCP Server container: streamable HTTP on :8000, non-root, health check on /healthz.
# Mount the Velociraptor API client config read-only and point VELOCIRAPTOR_API_KEY at it, e.g.
#   -v ./api.config.yaml:/config/api.config.yaml:ro -e VELOCIRAPTOR_API_KEY=/config/api.config.yaml
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY velociraptor_mcp_server ./velociraptor_mcp_server
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10005 mcp
COPY --from=build /install /usr/local
ENV MCP_TRANSPORT=http \
    MCP_SERVER_HOST=0.0.0.0 \
    MCP_SERVER_PORT=8000 \
    VELOCIRAPTOR_API_KEY=/config/api.config.yaml \
    PYTHONUNBUFFERED=1
USER mcp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1
CMD ["velociraptor-mcp-server"]
