#!/usr/bin/env python3
"""
BreachGraph: Main Interactive CLI Entry Point
==============================================
Provides an interactive menu for hackathon demonstrations and testing:
- Scenario 1: Critical breach path with Min-Cut surgical cut and zero downtime.
- Scenario 2: Benign/isolated threat testing agent restraint (zero destructive action).
- Scenario 3: Custom node inspection.
- Scenario 4: 1-Click graph re-seeding for flawless demo video takes.
"""

import sys
import argparse
from typing import Dict, Any

from ui.terminal import TerminalUI
from agent.engine import AgentExecutionEngine
from graph.seed import seed_database
from graph.client import verify_graph_liveness, GraphConnectionError


def run_scenario_critical(engine: AgentExecutionEngine, ui: TerminalUI):
    """Executes Scenario 1: External Trojan on Web-Server-Public."""
    ui.print_alert(
        origin_node="Web-Server-Public",
        description="Trojan.Generic / Reverse Shell detected on port 8443 (CVE-2024-4577)",
        severity="CRITICAL"
    )

    def handle_event(event_type: str, data: Any):
        if event_type == "STEP_START":
            ui.print_step(data)
        elif event_type == "BLAST_RADIUS_CONTRAST":
            ui.print_blast_radius_contrast(data)
        elif event_type == "CHOKEPOINT_DETECTED":
            ui.console.print(f"[bold cyan]Shortest Attack Path Identified:[/bold cyan] {data['total_hops']} hops via {data['edge_types']}")
        elif event_type == "TRADEOFF_EVALUATED":
            ui.print_tradeoff_matrix(data)
        elif event_type == "REMEDIATION_EXECUTED":
            ui.console.print(f"[bold green]✔ Action Applied:[/bold green] {data['action']} on {data['target']}")
        elif event_type == "VERIFICATION_COMPLETE":
            pass

    res = engine.run_deterministic_investigation(
        origin_node="Web-Server-Public",
        high_value_target="Customer-CreditCard-DB",
        event_callback=handle_event
    )

    if res["status"] == "INCIDENT_NEUTRALIZED":
        ui.print_remediation_summary(
            rem_data={
                "target": res["severed_cut_vertex"],
                "target_type": "UserKey",
                "action": "CREDENTIAL_REVOKED",
                "severed_edge": "AUTHENTICATES_TO"
            },
            verif_data={
                "remaining_attack_paths": 0,
                "protected_service": "Checkout-Billing-Service",
                "preserved_revenue_per_hr": res["preserved_revenue_per_hr"]
            },
            report_file=res["forensic_report"]
        )


def run_scenario_restraint(engine: AgentExecutionEngine, ui: TerminalUI):
    """Executes Scenario 2: Agent Restraint on Analytics-Worker."""
    ui.print_alert(
        origin_node="Analytics-Worker",
        description="Suspicious internal port scan / recon activity detected",
        severity="MEDIUM"
    )

    def handle_event(event_type: str, data: Any):
        if event_type == "STEP_START":
            ui.print_step(data)
        elif event_type == "BLAST_RADIUS_CONTRAST":
            ui.print_blast_radius_contrast(data)
        elif event_type == "AGENT_RESTRAINT":
            ui.print_restraint_summary("Analytics-Worker", data)

    engine.run_deterministic_investigation(
        origin_node="Analytics-Worker",
        high_value_target="Customer-CreditCard-DB",
        event_callback=handle_event
    )


def run_scenario_custom(engine: AgentExecutionEngine, ui: TerminalUI):
    """Prompts for custom host and targets."""
    ui.console.print("\n[bold cyan]Custom Graph Asset Investigation[/bold cyan]")
    target_node = input("Enter node name to investigate (e.g. Web-Server-Public, Analytics-Worker): ").strip()
    if not target_node:
        ui.console.print("[red]Node name cannot be blank.[/red]")
        return

    ui.print_alert(origin_node=target_node, description="Manual Security Audit Investigation", severity="CUSTOM")
    engine.run_deterministic_investigation(
        origin_node=target_node,
        event_callback=lambda et, d: ui.print_step(d) if et == "STEP_START" else None
    )


def main():
    parser = argparse.ArgumentParser(description="BreachGraph: Autonomous Incident Response Commander")
    parser.add_argument("--plain", action="store_true", help="Plain text output for screen readers and accessibility")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4], help="Run a specific scenario non-interactively")
    args = parser.parse_args()

    ui = TerminalUI(plain_mode=args.plain)
    ui.print_banner()

    # Verify FalkorDB connection immediately (Rule 3)
    try:
        verify_graph_liveness()
    except GraphConnectionError as e:
        ui.console.print(f"[bold red]{e}[/bold red]")
        sys.exit(1)

    engine = AgentExecutionEngine()

    if args.scenario:
        if args.scenario == 1:
            run_scenario_critical(engine, ui)
        elif args.scenario == 2:
            run_scenario_restraint(engine, ui)
        elif args.scenario == 3:
            run_scenario_custom(engine, ui)
        elif args.scenario == 4:
            seed_database(verbose=True)
        return

    # Interactive Loop
    while True:
        ui.console.print("\n[bold yellow]┌── SELECT INCIDENT SCENARIO ───────────────────────────────────────────┐[/bold yellow]")
        ui.console.print("[bold yellow]│[/bold yellow] [1] [bold red]Scenario 1:[/bold red] External Trojan on Web-Server-Public (Critical Vault Path) [bold yellow]│[/bold yellow]")
        ui.console.print("[bold yellow]│[/bold yellow] [2] [bold blue]Scenario 2:[/bold blue] Insider Recon on Analytics-Worker (Safe Isolated Path)      [bold yellow]│[/bold yellow]")
        ui.console.print("[bold yellow]│[/bold yellow] [3] [bold cyan]Scenario 3:[/bold cyan] Custom Target Node Investigation                             [bold yellow]│[/bold yellow]")
        ui.console.print("[bold yellow]│[/bold yellow] [4] [bold green]Scenario 4:[/bold green] Reset & Re-Seed Graph Topology (1-Click Reset for Video)    [bold yellow]│[/bold yellow]")
        ui.console.print("[bold yellow]│[/bold yellow] [5] Exit                                                               [bold yellow]│[/bold yellow]")
        ui.console.print("[bold yellow]└───[/bold yellow]───────────────────────────────────────────────────────────────────[bold yellow]┘[/bold yellow]")

        choice = input("\nEnter choice [1-5]: ").strip()

        if choice == "1":
            run_scenario_critical(engine, ui)
        elif choice == "2":
            run_scenario_restraint(engine, ui)
        elif choice == "3":
            run_scenario_custom(engine, ui)
        elif choice == "4":
            seed_database(verbose=True)
        elif choice == "5":
            ui.console.print("\n[bold green]Goodbye! Best of luck in the hackathon![/bold green]")
            break
        else:
            ui.console.print("[bold red]Invalid option. Please enter 1-5.[/bold red]")


if __name__ == "__main__":
    main()
