"""
BreachGraph: FalkorDB Connection & Client Manager
=================================================
Manages connections to FalkorDB (Local Docker or FalkorDB Cloud) with
resilient exponential retries and strict Rule 3 liveness verification.
"""

import time
import sys
from typing import Optional
from falkordb import FalkorDB, Graph
from config.settings import (
    FALKORDB_HOST,
    FALKORDB_PORT,
    FALKORDB_PASSWORD,
    FALKORDB_USERNAME,
    FALKORDB_GRAPH_NAME
)


class GraphConnectionError(Exception):
    """Raised when FalkorDB graph engine cannot be reached."""
    pass


def get_falkordb_client(max_retries: int = 3, retry_delay: float = 2.0) -> FalkorDB:
    """
    Establish a connection to the FalkorDB instance with automated retries.
    
    Args:
        max_retries: Number of connection attempts before failing.
        retry_delay: Delay in seconds between connection retries.
        
    Returns:
        FalkorDB: Connected client instance.
        
    Raises:
        GraphConnectionError: If connection cannot be established after max_retries.
    """
    for attempt in range(1, max_retries + 1):
        try:
            # Build connection kwargs, omitting credentials if None (local Docker compatibility)
            connect_kwargs = {
                "host": FALKORDB_HOST,
                "port": FALKORDB_PORT
            }
            if FALKORDB_PASSWORD:
                connect_kwargs["password"] = FALKORDB_PASSWORD
            if FALKORDB_USERNAME:
                connect_kwargs["username"] = FALKORDB_USERNAME

            db = FalkorDB(**connect_kwargs)
            # Ping to verify connection works
            db.connection.ping()
            return db
        except Exception as e:
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                error_msg = (
                    f"\n[CRITICAL ERROR] Failed to connect to FalkorDB at {FALKORDB_HOST}:{FALKORDB_PORT} after {max_retries} attempts.\n"
                    f"Under Hackathon Rule 3 (Graph Extraction Rule), this agent CANNOT operate without FalkorDB.\n"
                    f"Details: {str(e)}\n\n"
                    f"TROUBLESHOOTING:\n"
                    f"1. If running locally with Docker: Run 'docker compose up -d' and wait 3 seconds.\n"
                    f"2. If using FalkorDB Cloud: Verify FALKORDB_HOST, FALKORDB_PORT, and FALKORDB_PASSWORD in your .env file.\n"
                )
                raise GraphConnectionError(error_msg) from e


def get_graph(graph_name: str = FALKORDB_GRAPH_NAME) -> Graph:
    """
    Retrieve or create the named graph instance in FalkorDB.
    
    Args:
        graph_name: Name of the graph partition (defaults to BreachGraph).
        
    Returns:
        Graph: FalkorDB Graph object.
    """
    db = get_falkordb_client()
    return db.select_graph(graph_name)


def verify_graph_liveness(graph: Optional[Graph] = None) -> bool:
    """
    Strict Rule 3 assertion: Verifies the FalkorDB engine is live and responsive.
    
    Returns:
        bool: True if FalkorDB is live and responsive.
    """
    try:
        db = get_falkordb_client()
        return bool(db.connection.ping())
    except Exception as e:
        raise GraphConnectionError(f"Rule 3 Violation: FalkorDB liveness check failed: {e}") from e
