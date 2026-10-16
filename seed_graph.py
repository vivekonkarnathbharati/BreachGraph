#!/usr/bin/env python3
"""
Root runner for initializing or resetting the BreachGraph topology in FalkorDB.
Usage:
    python seed_graph.py
"""

import sys
from graph.seed import seed_database
from graph.client import GraphConnectionError

if __name__ == "__main__":
    try:
        seed_database(verbose=True)
    except GraphConnectionError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
