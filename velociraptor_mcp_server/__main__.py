"""
Main CLI entry point for the Velociraptor MCP Server.
"""

import argparse
import logging
import sys

from dotenv import load_dotenv

from .config import Config
from .server import create_server

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CLI."""
    parser = argparse.ArgumentParser(
        description="Velociraptor MCP Server - Model Context Protocol server for Velociraptor DFIR platform",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=None,
        help="MCP transport (default: MCP_TRANSPORT env var, else stdio)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind the HTTP transport to (default: MCP_SERVER_HOST env var, else 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port for the HTTP transport (default: MCP_SERVER_PORT env var, else 8000)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--api-config",
        help="Path to Velociraptor api.config.yaml file (overrides VELOCIRAPTOR_API_KEY env var)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.2.0")

    return parser


def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Create config from environment
    config = Config.from_env()

    # Override with CLI arguments
    if args.api_config:
        config.velociraptor.api_key = args.api_config
    if args.no_ssl_verify:
        config.velociraptor.ssl_verify = False

    # CLI flags override the environment only when given.
    if args.transport:
        config.server.transport = args.transport
    if args.host:
        config.server.host = args.host
    if args.port:
        config.server.port = args.port
    config.server.log_level = args.log_level

    try:
        # Validate configuration
        config.validate()
        config.setup_logging()

        # Create and start server
        server = create_server(config)
        server.start()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Failed to start server: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
