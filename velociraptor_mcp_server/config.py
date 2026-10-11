"""
Configuration management for Velociraptor MCP Server.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class VelociraptorConfig:
    """Configuration for a Velociraptor server instance."""

    api_key: str  # Path to api.config.yaml file or direct API key
    ssl_verify: bool = True
    timeout: int = 30
    max_rows: int = 1000  # Server-side cap on rows returned by any query

    @classmethod
    def from_env(cls, prefix: str = "VELOCIRAPTOR") -> "VelociraptorConfig":
        """Create configuration from environment variables."""
        return cls(
            api_key=os.getenv(f"{prefix}_API_KEY", ""),
            ssl_verify=os.getenv(f"{prefix}_SSL_VERIFY", "true").lower()
            not in {"0", "false", "no"},
            timeout=int(os.getenv(f"{prefix}_TIMEOUT", "30")),
            max_rows=int(os.getenv(f"{prefix}_MAX_ROWS", "1000")),
        )

    def validate(self) -> None:
        """Validate configuration."""
        if not self.api_key:
            raise ValueError("Velociraptor API key/config path is required")
        # If api_key looks like a file path, validate it exists
        if self.api_key.endswith(".yaml") or self.api_key.endswith(".yml"):
            if not os.path.exists(self.api_key):
                raise ValueError(f"Velociraptor API config file not found: {self.api_key}")


@dataclass
class ServerConfig:
    """Configuration for the MCP server."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    disabled_tools: List[str] = field(default_factory=list)
    disabled_categories: List[str] = field(default_factory=list)
    read_only: bool = False
    transport: str = "stdio"
    auth_token: str = ""
    max_output_chars: int = 32000

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        disabled_tools = []
        if tools_str := os.getenv("VELOCIRAPTOR_DISABLED_TOOLS"):
            disabled_tools = [tool.strip() for tool in tools_str.split(",")]

        disabled_categories = []
        if categories_str := os.getenv("VELOCIRAPTOR_DISABLED_CATEGORIES"):
            disabled_categories = [cat.strip() for cat in categories_str.split(",")]

        return cls(
            host=os.getenv("MCP_SERVER_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_SERVER_PORT", "8000")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            disabled_tools=disabled_tools,
            disabled_categories=disabled_categories,
            read_only=os.getenv("VELOCIRAPTOR_READ_ONLY", "false").lower() in {"1", "true", "yes"},
            transport=os.getenv("MCP_TRANSPORT", "stdio").lower(),
            auth_token=os.getenv("MCP_AUTH_TOKEN", ""),
            max_output_chars=int(os.getenv("MCP_MAX_OUTPUT_CHARS", "32000")),
        )


@dataclass
class Config:
    """Main configuration class."""

    velociraptor: VelociraptorConfig
    server: ServerConfig

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls(velociraptor=VelociraptorConfig.from_env(), server=ServerConfig.from_env())

    def validate(self) -> None:
        """Validate all configuration."""
        self.velociraptor.validate()

    def setup_logging(self) -> None:
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.server.log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
