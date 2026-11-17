"""
Reproducible end-to-end demonstration (no dataset needed).

    python demo.py            # fast path (a few seconds), no dataset needed
    python demo.py --full     # also runs the full 2,000-flow pipeline (needs the dataset)

Steps
  1. Run the automated test suite (non-destructive, temporary folders only).
  2. Controlled endpoint healing: successful + failed scenario (live printout).
  3. Controlled multi-stage APT campaign across two simulated hosts.
  4. Open the SOC dashboard of the latest full standard run
     (or of the new run when --full is given).

Everything is written to a new runs/<RUN_ID>-demo/ folder. Historical files,
the model, the Q-table and the dataset are only read.
"""

import argparse
import contextlib
import io
import json
import subprocess
import sys
import unittest

import project_config as cfg


def banner(text):
    print("\n" + "=" * 78 + f"\n{text}\n" + "=" * 78, flush=True)


def quiet():
    """Hide the modules' own 'Ready'/'Loaded' start-up prints during the demo."""
    return contextlib.redirect_stdout(io.StringIO())


def latest_standard_run():
    runs = []
    for folder in sorted(cfg.RUNS_DIR.glob("*")):
        summary = folder / "pipeline_summary.json"
        if summary.exists() and (folder / "dashboard.html").exists():
            data = json.loads(summary.read_text(encoding="utf-8"))
            if data.get("evaluation_set") == "STANDARD_PHASE4":
                runs.append(folder)
    return runs[-1] if runs else None


def main():

    parser = argparse.ArgumentParser(description="End-to-end demonstration")
    parser.add_argument("--full", action="store_true", help="Run the full pipeline (reads the 9.2M-row dataset)")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    banner("STEP 1 - AUTOMATED TESTS")
    console = sys.stdout
    with quiet():
        suite = unittest.defaultTestLoader.discover(str(cfg.BASE_DIR / "tests"))
        result = unittest.TextTestRunner(stream=console, verbosity=1).run(suite)
    if not result.wasSuccessful():
        print("Tests failed - stopping the demo so a broken build is not presented.")
        sys.exit(1)

    with quiet():
        from apt_simulation import run_apt_campaign
        from endpoint_healing import run_demonstration
        from response_verifier import ResponseVerifier
        from self_healing_engine import SelfHealingEngine
        from threat_memory import ThreatMemory

    run_id = cfg.new_run_id() + "-demo"
    run_dir = cfg.create_run_dir(run_id)
    with quiet():
        memory = ThreatMemory(str(run_dir / "demo.db"))
        verifier, engine = ResponseVerifier(), SelfHealingEngine()
    incident = {"event_id": "DEMO-INCIDENT (not a pipeline event)",
                "initial_action": "ALLOW", "healing_action": "ESCALATE", "healing_severity": "HIGH"}

    try:
        banner("STEP 2 - CONTROLLED ENDPOINT HEALING (SIMULATED ENDPOINTS)")
        for r in run_demonstration(run_dir, run_id, [incident], verifier, engine, memory):
            s = r["integrity_summary"]
            print(f"\n{r['host_id']} - {r['scenario']} -> {r['recovery_status']}")
            print(f"  quarantined : {[q['original_path'] for q in r['quarantine_actions']]}")
            print(f"  persistence : removed {r['persistence_removed']}")
            print(f"  restored    : {[a['path'] for a in r['restoration_actions'] if a['restored']]}")
            print(f"  refused     : {[a['path'] for a in r['restoration_actions'] if not a['restored']]}")
            print(f"  SHA-256     : {s['files_passed']}/{s['files_checked']} files match the trusted baseline")
            print(f"  decision    : {r['final_healing_decision']['healing_action']} -> "
                  f"{r['final_healing_decision']['recommended_action']}")
            for reason in r["failure_reasons"]:
                print(f"  FAILURE     : {reason}")

        banner("STEP 3 - MULTI-STAGE APT CAMPAIGN (2 SIMULATED HOSTS)")
        apt = run_apt_campaign(run_dir, run_id, verifier, engine, memory, incident)
        for t in apt["timeline"]:
            print(f"  {t['seq']}. {t['tactic_id']} {t['tactic']:30s} {t['host_id']}  {t['artifact']}")
        for c in apt["correlations"]:
            print(f"  correlation : same implant hash {c['sha256'][:12]}... on {c['from_hosts']} -> {c['to_host']}")
        for h, resp in apt["responses"].items():
            print(f"  {h} response: {resp['recovery_status']} ({resp['integrity_summary']['files_passed']}/"
                  f"{resp['integrity_summary']['files_checked']} SHA-256)")
        print(f"  VERDICT     : {apt['verdict']}")
    finally:
        memory.close()

    print(f"\nDemo evidence saved in {run_dir}")

    banner("STEP 4 - SOC DASHBOARD")
    if args.full:
        cmd = [sys.executable, str(cfg.BASE_DIR / "pipeline.py")] + (["--no-browser"] if args.no_browser else [])
        print("Running:", " ".join(cmd))
        sys.exit(subprocess.call(cmd, cwd=str(cfg.BASE_DIR)))

    run = latest_standard_run()
    if run is None:
        example = cfg.BASE_DIR / "examples" / "sample_run" / "dashboard.html"
        print("No local full run yet (python pipeline.py needs the dataset).")
        if example.exists():
            print(f"Opening the bundled example dashboard: {example}")
            if not args.no_browser:
                from dashboard_export import open_dashboard
                print("Opened in", open_dashboard(example))
        return
    from dashboard_export import open_dashboard, validate_dashboard
    ok, detail = validate_dashboard(run / "dashboard.html", run.name)
    print(f"Latest full run: {run.name} - validation {'OK' if ok else 'FAILED'} ({detail})")
    if ok and not args.no_browser:
        print("Opened in", open_dashboard(run / "dashboard.html"))


if __name__ == "__main__":
    main()
