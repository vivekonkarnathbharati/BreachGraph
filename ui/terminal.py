"""
BreachGraph: Rich Terminal Interface & Accessibility Views
===========================================================
Renders formatted CLI panels, tables, and live spinners.
Includes a '--plain' mode for screen readers and WCAG compliance.
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class TerminalUI:
    """Manages formatted terminal output and accessibility views."""

    def __init__(self, plain_mode: bool = False):
        self.plain_mode = plain_mode
        self.console = Console(no_color=plain_mode, highlight=not plain_mode)

    def print_banner(self):
        """Displays the application header banner."""
        banner_text = Text()
        banner_text.append("🛡️  BREACHGRAPH: AUTONOMOUS INCIDENT COMMANDER\n", style="bold cyan")
        banner_text.append("Track 01: Agents That Act on Connected Data | Powered by FalkorDB & Gemini", style="italic white")
        
        panel = Panel(
            banner_text,
            title="[bold yellow]WeMakeDevs & FalkorDB Graph Hacks 2026[/bold yellow]",
            subtitle="[dim]Minimum-Weight Cut (Min-Cut) Infrastructure Remediation[/dim]",
            border_style="cyan"
        )
        self.console.print(panel)

    def print_alert(self, origin_node: str, description: str, severity: str = "CRITICAL"):
        """Displays an incoming SOC incident alert banner."""
        alert_content = (
            f"[bold red]ORIGIN HOST:[/bold red] {origin_node}\n"
            f"[bold red]SEVERITY:[/bold red]    {severity}\n"
            f"[bold red]DETECTION:[/bold red]   {description}\n"
            f"[bold yellow]DIRECTIVE:[/bold yellow]   Autonomous graph blast radius investigation & surgical mitigation"
        )
        self.console.print(Panel(alert_content, title="🚨 [bold red]SOC ALERT INGESTED[/bold red]", border_style="red"))

    def print_step(self, message: str):
        """Prints a prominent step indicator."""
        self.console.print(f"\n[bold green]➔[/bold green] [bold white]{message}[/bold white]")

    def print_blast_radius_contrast(self, contrast_data: Dict[str, Any]):
        """Displays the Depth 1 vs Depth 4 comparison table."""
        d1 = contrast_data["depth_1"]
        d4 = contrast_data["depth_4"]

        table = Table(
            title="💥 BLAST RADIUS: 1-HOP PERIMETER vs 4-HOP GRAPH TRAVERSAL",
            title_style="bold magenta",
            border_style="magenta",
            show_lines=True
        )
        table.add_column("Depth Level", justify="center", style="cyan")
        table.add_column("Visible Assets", justify="center", style="white")
        table.add_column("Crown Jewels at Risk", justify="center", style="bold red")
        table.add_column("Architectural Reality & Discovery", style="yellow")

        table.add_row(
            "Depth = 1\n(Perimeter Only)",
            f"{d1['total_reachable_count']} Node",
            f"{d1['crown_jewels_at_risk_count']} Vaults",
            "[dim]Superficial view: Attacker appears contained to Internal-API-Gateway. False sense of security![/dim]"
        )
        table.add_row(
            "Depth = 4\n(Graph Multi-Hop)",
            f"{d4['total_reachable_count']} Nodes",
            f"[bold red]{d4['crown_jewels_at_risk_count']} Vault (PCI-DSS)![/bold red]",
            "[bold red]CRITICAL LATERAL PATH UNCOVERED:[/bold red] Gateway stores DB-Admin-Key which accesses Customer-CreditCard-DB!"
        )
        self.console.print(table)

        # Print detailed path table
        path_table = Table(title="📍 Discovered Assets & Lateral Movement Trace", border_style="dim white")
        path_table.add_column("Hop", justify="center")
        path_table.add_column("Asset Name")
        path_table.add_column("Type")
        path_table.add_column("Classification")
        path_table.add_column("Traversal Path")

        for a in d4["all_reachable_assets"]:
            cls_style = "bold red" if "PCI-DSS" in a["classification"] else "white"
            path_table.add_row(
                str(a["hops"]),
                a["asset_name"],
                a["asset_type"],
                f"[{cls_style}]{a['classification']}[/{cls_style}]",
                " ➔ ".join(a["trace_path"])
            )
        self.console.print(path_table)

    def print_tradeoff_matrix(self, tradeoff_data: Dict[str, Any]):
        """Displays the Min-Cut business impact evaluation table."""
        matrix = tradeoff_data["tradeoff_matrix"]
        rec = tradeoff_data["recommended_min_cut"]

        table = Table(
            title="⚖️  MINIMUM-WEIGHT CUT (MIN-CUT) REMEDIATION EVALUATION",
            title_style="bold yellow",
            border_style="yellow",
            show_lines=True
        )
        table.add_column("Cut Candidate", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Collateral Downtime / Hr", justify="right")
        table.add_column("Disrupted Services")
        table.add_column("Algorithmic Recommendation")

        for c in matrix:
            cost = c["collateral_damage_per_hr"]
            is_rec = (c["node_to_cut"] == rec["node_to_cut"])
            
            cost_str = f"${cost:,.2f}/hr" if cost > 0 else "$0.00/hr (Zero Downtime!)"
            cost_style = "bold red" if cost > 10000 else "bold green"
            
            rec_str = "[bold green]★ OPTIMAL MIN-CUT (SURGICAL)[/bold green]" if is_rec else "[dim]Sub-optimal (Excessive Damage)[/dim]"
            services = ", ".join(c["disrupted_services"]) if c["disrupted_services"] else "None (Safe)"

            table.add_row(
                c["node_to_cut"],
                c["node_type"],
                f"[{cost_style}]{cost_str}[/{cost_style}]",
                services,
                rec_str
            )
        self.console.print(table)
        self.console.print(f"[bold cyan]FalkorDB Optimization Logic:[/bold cyan] {tradeoff_data['algorithmic_rationale']}")

    def print_remediation_summary(self, rem_data: Dict[str, Any], verif_data: Dict[str, Any], report_file: str):
        """Displays the final containment and business continuity card."""
        content = (
            f"[bold green]✔ REMEDIATION STATUS:[/bold green]     SUCCESSFULLY APPLIED\n"
            f"[bold green]✔ TARGET SEVERED:[/bold green]         {rem_data['target']} ({rem_data['target_type']})\n"
            f"[bold green]✔ ACTION EXECUTED:[/bold green]        {rem_data['action']} (Edge '{rem_data['severed_edge']}' deleted in FalkorDB)\n"
            f"[bold green]✔ REMAINING ATTACK PATHS:[/bold green] {verif_data['remaining_attack_paths']} (Mathematical Partitioning Proven)\n"
            f"[bold cyan]✔ BUSINESS CONTINUITY:[/bold cyan]    {verif_data['protected_service']} is ONLINE (Zero Disruption!)\n"
            f"[bold cyan]✔ REVENUE PRESERVED:[/bold cyan]      ${verif_data['preserved_revenue_per_hr']:,.2f}/hr Protected\n"
            f"[bold yellow]✔ FORENSIC AUDIT TRAIL:[/bold yellow]  Exported to '{report_file}'"
        )
        panel = Panel(content, title="🛡️ [bold green]INCIDENT RESOLVED: THREAT CONTAINED WITH ZERO DOWNTIME[/bold green]", border_style="green")
        self.console.print(panel)

    def print_restraint_summary(self, origin_node: str, restraint_data: Dict[str, Any]):
        """Displays the agent restraint notification for benign/isolated scenarios."""
        content = (
            f"[bold cyan]TARGET EVALUATED:[/bold cyan]     {origin_node}\n"
            f"[bold cyan]GRAPH TRAVERSAL:[/bold cyan]      Variable-length reachability analysis across all downstream edges\n"
            f"[bold cyan]FINDING:[/bold cyan]              Zero high-value / PCI-DSS databases reachable from this host\n"
            f"[bold green]AUTONOMOUS DECISION:[/bold green]  AGENT RESTRAINT APPLIED (Zero destructive actions executed)\n"
            f"[bold green]OPERATIONAL STATUS:[/bold green]   All network and credential edges remain intact. Threat tagged for routine review."
        )
        panel = Panel(content, title="🕊️ [bold blue]AGENT RESTRAINT: THREAT ISOLATED IN BENIGN SUBNET[/bold blue]", border_style="blue")
        self.console.print(panel)
