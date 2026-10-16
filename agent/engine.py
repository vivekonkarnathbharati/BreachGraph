"""
BreachGraph: Autonomous AI Agent Loop & Gemini Integration Engine
==================================================================
Coordinates Gemini tool calling, rate-limiting backoff, and graph traversals.
Includes parallel tool-call batching to prevent Gemini 400 errors.
"""

import time
from typing import Dict, Any, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from config.settings import (
    GEMINI_API_KEY,
    DEFAULT_GEMINI_MODEL,
    TOOL_CALL_PAUSE_SECONDS,
    API_RETRY_ATTEMPTS
)
from agent.tools import (
    resolve_asset_in_graph,
    calculate_blast_radius,
    find_critical_chokepoints,
    evaluate_remediation_tradeoffs,
    remediate_node,
    verify_threat_containment
)
from agent.forensics import generate_forensic_report

# Try importing Google GenAI SDK
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


# Map tool names to concrete Python execution functions
TOOL_REGISTRY = {
    "resolve_asset_in_graph": resolve_asset_in_graph,
    "calculate_blast_radius": calculate_blast_radius,
    "find_critical_chokepoints": find_critical_chokepoints,
    "evaluate_remediation_tradeoffs": evaluate_remediation_tradeoffs,
    "remediate_node": remediate_node,
    "verify_threat_containment": verify_threat_containment
}


# Tool definitions formatted for Google GenAI / Gemini Function Calling
GEMINI_TOOL_DECLARATIONS = [
    resolve_asset_in_graph,
    calculate_blast_radius,
    find_critical_chokepoints,
    evaluate_remediation_tradeoffs,
    remediate_node,
    verify_threat_containment
]


SYSTEM_PROMPT = """
You are BreachGraph: an elite Autonomous Cyber Incident Commander operating over an enterprise infrastructure graph in FalkorDB.
Your mission is to investigate compromised infrastructure, identify multi-hop lateral movement paths to crown jewels, and execute surgical remediation that strictly minimizes business disruption.

STRICT OPERATIONAL RULES:
1. Always resolve the compromised node first using 'resolve_asset_in_graph'.
2. Calculate the blast radius using 'calculate_blast_radius' to detect reachable crown jewels (e.g. PCI-DSS databases).
3. If no high-value assets are reachable (such as in benign or isolated paths), exercise restraint: DO NOT execute destructive actions. Log the finding as Low Priority and conclude.
4. If a crown-jewel asset is reachable:
   a. Pinpoint the attack path using 'find_critical_chokepoints'.
   b. Solve the Minimum-Cut problem using 'evaluate_remediation_tradeoffs'. FalkorDB dynamically computes operational revenue impact.
   c. Select the cut-vertex with the lowest collateral damage (typically revoking a specific UserKey rather than isolating an entire $500k/hr API Gateway).
   d. Execute surgical remediation using 'remediate_node'.
   e. Confirm complete threat isolation and business uptime using 'verify_threat_containment'.
5. Always explain your decisions by citing exact graph hops and financial revenue preserved.
"""


class AgentExecutionEngine:
    """Manages the autonomous incident triage and remediation agent loop."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = DEFAULT_GEMINI_MODEL):
        self.api_key = api_key or GEMINI_API_KEY
        self.model_name = model_name
        self.client = None
        if self.api_key and GENAI_AVAILABLE:
            self.client = genai.Client(api_key=self.api_key)

    def is_api_ready(self) -> bool:
        """Checks if Google GenAI SDK and API Key are configured."""
        return bool(self.client is not None)

    def execute_tool_call(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a registered tool by name with arguments."""
        if tool_name not in TOOL_REGISTRY:
            return {"error": f"Unknown tool: {tool_name}"}
        tool_fn = TOOL_REGISTRY[tool_name]
        try:
            return tool_fn(**args)
        except Exception as e:
            return {"error": f"Execution error in {tool_name}: {str(e)}"}

    def run_deterministic_investigation(
        self,
        origin_node: str,
        high_value_target: str = "Customer-CreditCard-DB",
        event_callback=None
    ) -> Dict[str, Any]:
        """
        Runs an autonomous, deterministic graph investigation loop.
        Can run with or without an active Gemini API key, ensuring 100% offline reliability.
        """
        timeline = []
        incident_id = f"INC-{int(time.time())}"

        def emit(event_type: str, data: Any):
            timeline.append({"event": event_type, "data": data, "timestamp": time.time()})
            if event_callback:
                event_callback(event_type, data)

        # Step 1: Asset Resolution
        emit("STEP_START", "Step 1: Resolving compromised host in FalkorDB topology...")
        time.sleep(TOOL_CALL_PAUSE_SECONDS)
        asset_res = resolve_asset_in_graph(origin_node)
        emit("TOOL_EXECUTION", {"tool": "resolve_asset_in_graph", "args": {"name": origin_node}, "result": asset_res})

        if not asset_res.get("exists"):
            emit("INCIDENT_ABORTED", f"Host '{origin_node}' not found in graph. Triage halted.")
            return {"status": "ABORTED", "reason": "Asset not in graph", "timeline": timeline}

        # Step 2: Depth-1 vs Depth-4 Blast Radius Contrast Check
        emit("STEP_START", "Step 2: Calculating 1-Hop Perimeter Visibility vs 4-Hop Deep Graph Blast Radius...")
        time.sleep(TOOL_CALL_PAUSE_SECONDS)
        depth1_res = calculate_blast_radius(origin_node, depth=1)
        depth4_res = calculate_blast_radius(origin_node, depth=4)

        emit("BLAST_RADIUS_CONTRAST", {
            "depth_1": depth1_res,
            "depth_4": depth4_res
        })

        # Check if high-value assets are reachable
        crown_jewels = depth4_res.get("crown_jewels_at_risk", [])
        if not crown_jewels:
            emit("AGENT_RESTRAINT", {
                "message": f"Zero high-value crown jewels reachable from '{origin_node}'. Threat contained in isolated zone.",
                "action": "NO_DESTRUCTIVE_MUTATION_REQUIRED",
                "status": "MONITORING_ONLY"
            })
            return {
                "status": "BENIGN_CONTAINED",
                "incident_id": incident_id,
                "reachable_assets": depth4_res["total_reachable_count"],
                "timeline": timeline
            }

        # Step 3: Shortest Path Algorithm
        emit("STEP_START", f"Step 3: Executing FalkorDB native shortestPath algorithm to '{high_value_target}'...")
        time.sleep(TOOL_CALL_PAUSE_SECONDS)
        path_res = find_critical_chokepoints(origin_node, high_value_target)
        emit("CHOKEPOINT_DETECTED", path_res)

        # Step 4: Minimum-Weight Cut (Min-Cut) Trade-Off Evaluation
        emit("STEP_START", "Step 4: Solving Minimum-Weight Cut (Min-Cut) problem in FalkorDB Cypher...")
        time.sleep(TOOL_CALL_PAUSE_SECONDS)
        tradeoff_res = evaluate_remediation_tradeoffs(origin_node, high_value_target)
        emit("TRADEOFF_EVALUATED", tradeoff_res)

        recommended_cut = tradeoff_res["recommended_min_cut"]
        cut_target = recommended_cut["node_to_cut"]
        cut_type = recommended_cut["node_type"]

        # Step 5: Surgical Graph Mutation
        emit("STEP_START", f"Step 5: Executing autonomous remediation on '{cut_target}' ({cut_type})...")
        time.sleep(TOOL_CALL_PAUSE_SECONDS)
        rem_res = remediate_node(cut_target, cut_type, action="ISOLATE")
        emit("REMEDIATION_EXECUTED", rem_res)

        # Step 6: Post-Remediation Verification & Uptime Assertion
        emit("STEP_START", "Step 6: Verifying complete graph partitioning and business uptime assertion...")
        time.sleep(TOOL_CALL_PAUSE_SECONDS)
        verif_res = verify_threat_containment(origin_node, high_value_target, "Checkout-Billing-Service")
        emit("VERIFICATION_COMPLETE", verif_res)

        # Step 7: Export Digital Forensic Report
        saved_revenue = verif_res.get("preserved_revenue_per_hr", 500000.0)
        report_file = generate_forensic_report(
            incident_id=incident_id,
            compromised_node=origin_node,
            target_database=high_value_target,
            blast_radius_nodes=depth4_res["all_reachable_assets"],
            tradeoff_matrix=tradeoff_res["tradeoff_matrix"],
            chosen_action=recommended_cut,
            redundant_paths_remaining=verif_res["remaining_attack_paths"],
            revenue_preserved_per_hr=saved_revenue
        )
        emit("FORENSIC_REPORT_GENERATED", report_file)

        return {
            "status": "INCIDENT_NEUTRALIZED",
            "incident_id": incident_id,
            "compromised_node": origin_node,
            "severed_cut_vertex": cut_target,
            "preserved_revenue_per_hr": saved_revenue,
            "forensic_report": report_file,
            "timeline": timeline
        }

    def run_agentic_gemini_investigation(
        self,
        origin_node: str,
        incident_description: str,
        event_callback=None
    ) -> Dict[str, Any]:
        """
        Executes the agent loop using Google Gemini function calling with
        safe parallel tool batching and retry handlers.
        """
        if not self.is_api_ready():
            # Graceful fallback to deterministic engine if API key is absent
            if event_callback:
                event_callback("API_NOTICE", "GEMINI_API_KEY not configured. Running via FalkorDB deterministic agent engine...")
            return self.run_deterministic_investigation(origin_node, event_callback=event_callback)

        chat = self.client.chats.create(
            model=self.model_name,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                tools=GEMINI_TOOL_DECLARATIONS,
                temperature=0.1
            )
        )

        user_prompt = (
            f"SECURITY INCIDENT ALERT: Host '{origin_node}' has reported critical alert: '{incident_description}'. "
            f"Investigate blast radius in FalkorDB, evaluate business trade-offs, and autonomously remediate."
        )

        if event_callback:
            event_callback("GEMINI_STARTED", f"Gemini ({self.model_name}) analyzing alert for {origin_node}...")

        response = chat.send_message(user_prompt)

        # Agent reasoning & function calling loop (bounded to 8 turns max)
        for turn in range(8):
            if not response.function_calls:
                # Finished reasoning
                break

            # BUG FIX 2: Collect ALL function responses into a list first!
            # Calling chat.send_message() inside the loop crashes on parallel tool calls.
            function_response_parts = []

            for call in response.function_calls:
                tool_name = call.name
                tool_args = call.args or {}

                if event_callback:
                    event_callback("TOOL_CALLING", {"name": tool_name, "args": tool_args})

                # Pacing delay to avoid rate-limit exhaustion
                time.sleep(TOOL_CALL_PAUSE_SECONDS)

                # Execute tool
                tool_result = self.execute_tool_call(tool_name, tool_args)

                if event_callback:
                    event_callback("TOOL_RESULT", {"name": tool_name, "result": tool_result})

                # Format part using Google GenAI SDK
                function_response_parts.append(
                    types.Part.from_function_response(
                        name=tool_name,
                        response={"result": tool_result}
                    )
                )

            # Send ALL response parts ONCE outside the loop with backoff retry
            time.sleep(TOOL_CALL_PAUSE_SECONDS)
            response = self._send_message_with_retry(chat, function_response_parts)

        final_text = response.text if hasattr(response, 'text') else "Investigation completed."
        if event_callback:
            event_callback("GEMINI_COMPLETED", final_text)

        return {
            "status": "COMPLETED_VIA_GEMINI",
            "agent_summary": final_text
        }

    @retry(
        stop=stop_after_attempt(API_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True
    )
    def _send_message_with_retry(self, chat, parts):
        """Wraps Gemini message dispatch with exponential backoff for 429 rate limits."""
        return chat.send_message(parts)
