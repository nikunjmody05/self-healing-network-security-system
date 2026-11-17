"""
Standalone controlled endpoint-healing demonstration (no dataset needed).

    python demo_endpoint_healing.py

Writes to runs/<RUN_ID>-endpoint-demo/endpoint_sim/ and prints each step.
The triggering incident is a labelled DEMO incident, not a pipeline event;
for incidents from a real pipeline run use pipeline.py.
"""

import json

import project_config as cfg
from endpoint_healing import run_demonstration
from response_verifier import ResponseVerifier
from self_healing_engine import SelfHealingEngine
from threat_memory import ThreatMemory


def main():

    run_id = cfg.new_run_id() + "-endpoint-demo"
    run_dir = cfg.create_run_dir(run_id)

    demo_incident = {
        "event_id": "DEMO-INCIDENT (not from a pipeline run)",
        "initial_action": "ALLOW",
        "healing_action": "ESCALATE",
        "healing_severity": "HIGH",
    }

    memory = ThreatMemory(str(run_dir / "endpoint_demo.db"))

    try:
        results = run_demonstration(
            run_dir, run_id, [demo_incident],
            ResponseVerifier(), SelfHealingEngine(), memory,
        )
    finally:
        memory.close()

    for r in results:
        print("\n" + "=" * 72)
        print(f"{r['host_id']}  {r['scenario']}  ->  {r['recovery_status']}")
        print("=" * 72)
        for step in r["simulated_attack"]:
            print("  attack     :", step)
        print("  detected   :", json.dumps(r["detected"], default=str))
        for q in r["quarantine_actions"]:
            print("  quarantine :", q["original_path"], "->", q["quarantine_path"])
        print("  persistence removed:", r["persistence_removed"])
        for a in r["restoration_actions"]:
            print("  restore    :", a)
        for c in r["integrity_checks"]:
            print(f"  sha256     : {'PASS' if c['passed'] else 'FAIL'}  {c['path']}")
        print("  verifier   :", r["endpoint_verification"]["verification_status"],
              "-", r["endpoint_verification"]["reason"])
        print("  decision   :", r["final_healing_decision"]["healing_action"],
              "->", r["final_healing_decision"]["recommended_action"])
        for reason in r["failure_reasons"]:
            print("  FAILURE    :", reason)

    print(f"\nReports: {run_dir / 'endpoint_sim'}")


if __name__ == "__main__":
    main()
