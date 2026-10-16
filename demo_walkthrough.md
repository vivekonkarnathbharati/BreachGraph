# 🎬 BreachGraph: 2-Minute Demo Video Recording Script

> **Target Track:** Track 01 – *Agents That Act on Connected Data*  
> **Target Duration:** 1 minute 50 seconds to 2 minutes 10 seconds.  
> **Screen Setup:** Split your monitor into two halves:
> * **Left Side:** Terminal with `python agent.py` running in full color.
> * **Right Side:** Web Browser with **FalkorDB Browser** (`http://localhost:3000` or FalkorDB Cloud console).

---

## ⏱️ Video Timeline & Teleprompter Script

### [0:00 – 0:25] The Problem & FalkorDB Browser Initial State
* **What to Show on Screen:** Point your mouse at the right side of the screen on the FalkorDB Browser visual canvas. Run query: `MATCH (n)-[r]->(m) RETURN n, r, m`. The nodes are visually displayed.
* **What to Say (Out Loud):**
  > *"Hi everyone! I’m a first-year Computer Science student, and this is **BreachGraph**, an autonomous incident commander built for Track 1 of Graph Hacks.*
  > 
  > *In cloud security, an infected server is rarely the final target. Attackers move laterally across credentials to reach sensitive databases. Commercial tools give you passive dashboards and alerts, but leaving human analysts to respond manually takes hours. But if you blindly automate remediation with bash scripts, you accidentally shut down critical production gateways and cause massive outages.*
  > 
  > *BreachGraph solves this by formulating autonomous remediation as a **Minimum-Weight Cut problem** on connected infrastructure in FalkorDB."*

---

### [0:25 – 0:50] The Contrast Test: Proving Agent Restraint (Scenario 2)
* **What to Show on Screen:** On the left side in the terminal, launch `python agent.py`. Select option `[2]`.
* **What to Say (Out Loud):**
  > *"Before showing an attack, let’s test the agent’s intelligence and restraint. I'll trigger an alert on an internal worker: `Analytics-Worker`.*
  > 
  > *The agent queries FalkorDB, traverses downstream connections, and discovers zero paths to any high-value assets. Notice what happens: the agent **refuses to take destructive action**. It logs the alert for routine monitoring without severing any network connections. This proves our agent is making real contextual decisions based on connected data, not running a blind trigger."*

---

### [0:50 – 1:25] Critical Incident Triage & Min-Cut Trade-Off (Scenario 1)
* **What to Show on Screen:** In the terminal menu, select option `[1]` (`Web-Server-Public`).
* **What to Say (Out Loud):**
  > *"Now let's simulate a critical attack. A Trojan reverse-shell alert fires on `Web-Server-Public`.*
  > 
  > *First, look at the Blast Radius table on screen: at Depth 1, the attacker only appears to reach the API Gateway. But FalkorDB's multi-hop traversal reveals that 3 hops away, `Customer-CreditCard-DB`—a PCI-DSS vault with 250,000 records—is in imminent danger!*
  > 
  > *Next, our agent calls FalkorDB's native `shortestPath` algorithm and runs our dynamic Min-Cut Cypher query. Look at the trade-off matrix: isolating the Gateway stops the threat, but it inflicts **$500,000/hour** in collateral damage by crashing our Checkout Service!*
  > 
  > *Instead, the agent mathematically selects the optimal cut: **revoking `DB-Admin-Key` only**. Collateral damage: **$0.00/hr**!"*

---

### [1:25 – 1:50] Live Visual Verification & Forensic Artifact
* **What to Show on Screen:**
  1. Highlight the terminal output showing `✔ REMEDIATION STATUS: SUCCESS` and `✔ REVENUE PRESERVED: $500,000.00/hr`.
  2. Click over to FalkorDB Browser on the right side and click **Execute Query** again.
  3. Show the `[:AUTHENTICATES_TO]` edge has disappeared and the credential node is revoked!
* **What to Say (Out Loud):**
  > *"The agent executes the remediation live in FalkorDB. Let’s re-run the query in the FalkorDB Browser on the right... and look! The authentication link to the credit card database is physically severed, and the credential status is revoked!*
  > 
  > *Our agent runs a secondary assertion verifying that remaining attack vectors equal zero, while `Checkout-Billing-Service` remains 100% online. Finally, it exports an immutable digital forensic JSON report for PCI-DSS compliance."*

---

### [1:50 – 2:05] Closing Pitch & Rule 3 Compliance
* **What to Show on Screen:** Bring terminal or README back into focus, showing the public repo and code structure.
* **What to Say (Out Loud):**
  > *"Under Hackathon Rule 3, the graph is the indispensable intelligence layer. Without FalkorDB, the agent cannot compute multi-hop lateral movement, cannot evaluate business dependency trade-offs, and cannot verify containment.*
  > 
  > *BreachGraph proves how AI agents can act autonomously on connected data to protect enterprise infrastructure in seconds with zero business downtime. Thank you!"*

---

## 💡 Quick Tips for Recording
* **Mistake during a take?** Press `[4]` in the terminal menu to reset and re-seed the graph in 0.3 seconds!
* **Audio:** Speak clearly and with energy. You are presenting an enterprise-grade AI security architect tool.
* **Screen Recording:** Use QuickTime Player (`Cmd + Shift + 5`) or OBS Studio to record your full screen in 1080p.
