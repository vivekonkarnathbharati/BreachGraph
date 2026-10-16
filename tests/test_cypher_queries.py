"""
Unit Tests: Cypher Query Syntax & Parameterization Validation
==============================================================
Validates that all Cypher patterns are properly parameterized,
comply with FalkorDB OpenCypher syntax, and feature explicit bounds.
"""

import pytest
from graph.queries import (
    CYPHER_RESOLVE_NODE,
    CYPHER_BLAST_RADIUS,
    CYPHER_SHORTEST_PATH,
    CYPHER_MIN_CUT_TRADEOFF,
    CYPHER_CHECK_REMAINING_ATTACK_PATHS,
    CYPHER_CHECK_BUSINESS_UPTIME
)


def test_shortest_path_has_explicit_lower_bound():
    """Verify shortestPath uses [*1..5] with explicit lower bound 1."""
    assert "*1..5" in CYPHER_SHORTEST_PATH, "Shortest path query must use explicit '*1..5' lower bound"


def test_min_cut_uses_falkordb_safe_label_syntax():
    """Verify labels(candidate)[0] <> 'Database' is used instead of Neo4j colon syntax."""
    assert "labels(candidate)[0] <> 'Database'" in CYPHER_MIN_CUT_TRADEOFF, (
        "Min-Cut query must use 'labels(candidate)[0] <> \"Database\"' for FalkorDB compatibility"
    )
    assert "NOT candidate:Database" not in CYPHER_MIN_CUT_TRADEOFF, (
        "Neo4j colon expression 'NOT candidate:Database' is forbidden on unwound variables"
    )


def test_revenue_impact_property_name_consistency():
    """Verify exact property name 'revenue_impact_per_hr' is used across queries."""
    assert "revenue_impact_per_hr" in CYPHER_MIN_CUT_TRADEOFF
    assert "revenue_impact_per_hr" in CYPHER_CHECK_BUSINESS_UPTIME


def test_all_queries_are_parameterized():
    """Ensure zero string interpolation tokens (e.g. %s, {name}) in Cypher constants."""
    for query in [
        CYPHER_RESOLVE_NODE,
        CYPHER_BLAST_RADIUS,
        CYPHER_SHORTEST_PATH,
        CYPHER_MIN_CUT_TRADEOFF,
        CYPHER_CHECK_REMAINING_ATTACK_PATHS,
        CYPHER_CHECK_BUSINESS_UPTIME
    ]:
        assert "%s" not in query, "SQL-style %s formatting found in Cypher query"
        assert "$" in query, "Parameterized Cypher variables ($param) missing in query"
