"""
Velociraptor MCP Server - A Model Context Protocol server for Velociraptor DFIR integration.
"""

__version__ = "0.2.0"
__author__ = "SOCFortress"
__email__ = "info@socfortress.co"
__description__ = "MCP server for Velociraptor DFIR integration with LLMs"

from .client import VelociraptorClient
from .config import Config
from .server import VelociraptorMCPServer

__all__ = ["VelociraptorMCPServer", "VelociraptorClient", "Config"]
