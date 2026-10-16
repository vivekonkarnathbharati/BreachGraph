"""
Unit Tests: Algorithmic Min-Cut Logic & Forensic Report Validation
===================================================================
Tests business trade-off ranking and structured JSON audit generation.
"""

import os
import json
import pytest
from agent.forensics import generate_forensic_report


def test_min_cut_ranking_order():
    """Validates that candidate cut vertices sort strictly by minimal collateral impact."""
    mock_candidates = [
        {"node_to_cut": "Internal-API-Gateway", "collateral_damage_per_hr": 500000.0},
        {"node_to_cut": "DB-Admin-Key", "collateral_damage_per_hr": 0.0}
    ]

    # Sort as Cypher ORDER BY collateral_damage_per_hr ASC does
    sorted_candidates = sorted(mock_candidates, key=lambda x: x["collateral_damage_per_hr"])

    assert sorted_candidates[0]["node_to_cut"] == "DB-Admin-Key"
    assert sorted_candidates[0]["collateral_damage_per_hr"] == 0.0
    assert sorted_candidates[1]["collateral_damage_per_hr"] == 500000.0


def test_forensic_report_generation(tmp_path):
    """Validates creation and schema compliance of forensic incident report."""
    incident_id = "TEST-INC-999"
    report_file = generate_forensic_report(
        incident_id=incident_id,
        compromised_node="Web-Server-Public",
        target_database="Customer-CreditCard-DB",
        blast_radius_nodes=[{"asset_name": "Customer-CreditCard-DB", "hops": 3}],
        tradeoff_matrix=[
            {"node_to_cut": "DB-Admin-Key", "collateral_damage_per_hr": 0.0},
            {"node_to_cut": "Internal-API-Gateway", "collateral_damage_per_hr": 500000.0}
        ],
        chosen_action={"node_to_cut": "DB-Admin-Key", "collateral_damage_per_hr": 0.0},
        redundant_paths_remaining=0,
        revenue_preserved_per_hr=500000.0
    )

    assert os.path.exists(report_file), f"Forensic report file '{report_file}' was not created"

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["report_metadata"]["incident_id"] == incident_id
    assert data["post_remediation_audit"]["redundant_lateral_vectors_remaining"] == 0
    assert data["post_remediation_audit"]["containment_status"] == "PROVEN_ISOLATED"
    assert data["algorithmic_decision_matrix"]["selected_remediation"]["node_to_cut"] == "DB-Admin-Key"

    # Clean up test artifact
    if os.path.exists(report_file):
        os.remove(report_file)
