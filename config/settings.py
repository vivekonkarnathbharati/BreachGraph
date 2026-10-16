"""
BreachGraph: Centralized Configuration & Constants
===================================================
Eliminates magic numbers and centralizes all infrastructure parameters,
FalkorDB connection settings, and agent runtime constraints.
"""

import os
from typing import List
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- FalkorDB Connection Settings ---
FALKORDB_HOST: str = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT: int = int(os.getenv("FALKORDB_PORT", "6379"))

# Critical bug fix: Treat blank/empty string password as None to prevent Redis AUTH errors on local Docker
_raw_password = os.getenv("FALKORDB_PASSWORD", "")
FALKORDB_PASSWORD: str | None = _raw_password if _raw_password.strip() else None

_raw_username = os.getenv("FALKORDB_USERNAME", "")
FALKORDB_USERNAME: str | None = _raw_username if _raw_username.strip() else None

FALKORDB_GRAPH_NAME: str = os.getenv("FALKORDB_GRAPH_NAME", "BreachGraph")

# --- Agent & Gemini LLM Settings ---
GEMINI_API_KEY: str | None = os.getenv("GEMINI_API_KEY") or None
DEFAULT_GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Pacing delay between tool actions to respect Google AI Studio Free Tier rate limits (15 RPM)
TOOL_CALL_PAUSE_SECONDS: float = 2.0
API_RETRY_ATTEMPTS: int = 3
API_RETRY_BACKOFF_FACTOR: float = 2.0

# --- Graph Traversal & Algorithmic Bounds ---
MIN_TRAVERSAL_DEPTH: int = 1
MAX_TRAVERSAL_DEPTH: int = 5
MAX_REDUNDANT_PATH_CHECK_DEPTH: int = 5

# High-value asset classification tags that trigger Critical P0 Incident Escalation
CROWN_JEWEL_CLASSIFICATIONS: List[str] = [
    "PCI-DSS",
    "High-Value/PCI-DSS",
    "HIPAA_PHI",
    "Customer-Vault"
]

# Standard Node Labels in BreachGraph
LABEL_SERVER: str = "Server"
LABEL_DATABASE: str = "Database"
LABEL_USER_KEY: str = "UserKey"
LABEL_VULNERABILITY: str = "Vulnerability"
LABEL_SERVICE: str = "Service"

# Standard Relationship Types in BreachGraph
REL_NETWORK: str = "CAN_NETWORK_ACCESS"
REL_CREDENTIAL: str = "STORES_CREDENTIAL"
REL_AUTH: str = "AUTHENTICATES_TO"
REL_VULNERABILITY: str = "HAS_VULNERABILITY"
REL_DEPENDENCY: str = "DEPENDS_ON"
