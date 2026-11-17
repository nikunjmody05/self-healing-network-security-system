"""
Run-driven SOC dashboard generation.

pipeline.py calls ``export_dashboard`` at the end of a run. It writes:

    runs/<RUN_ID>/dashboard_data.js   window.RUN_DATA = {...}
    runs/<RUN_ID>/dashboard.html      copy of dashboard/soc_dashboard_template.html

The template is the project's SOC dashboard design with its run-dependent
values bound to RUN_DATA. dashboard_data.js is loaded with a
<script> tag, which works from file:// in Chrome, so no API server is needed.

Every run-dependent value comes from this run's events, summary, per-run
SQLite database and endpoint-healing reports. Historical training results
(e.g. detection_model.py accuracy) are labelled as historical in the template.
"""

import json
import math
import os
import shutil
import sqlite3
import subprocess
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path

import project_config as cfg


# Event schema expected by the V2 dashboard's explorers
V2_EVENT_MAP = {
    "step": "step",
    "event_id": "event_id",
    "true_label": "true_label",
    "prediction": "prediction",
    "confidence": "confidence",
    "threat_score": "threat_score",
    "severity": "severity",
    "rl_state": "state",
    "unseen_rl_state": "unseen_rl_state",
    "initial_action": "action",
    "initial_response": "response",
    "initial_status": "status",
    "initial_verification": "initial_verification_status",
    "initial_simulated_containment": "initial_simulated_containment",
    "recovery_required": "initial_recovery_required",
    "healing_action": "healing_action",
    "recommended_action": "recommended_action",
    "recovery_action": "recovery_action",
    "recovery_status": "recovery_status",
    "post_recovery_simulated_containment": "post_recovery_simulated_containment",
    "pattern_status": "pattern_status",
    "pattern_id": "pattern_id",
    "pattern_occurrences_before_event": "pattern_occurrences_before_event",
    "reward": "reward",
}

CHARTS = [
    "rl_evaluation_curve.png",
    "action_distribution_risk.png",
    "self_healing_recovery_comparison.png",
]

ACTIONS = ["ALLOW", "ALERT", "BLOCK"]


def _clean(value):
    """Make values JSON-safe (NaN -> None, numpy -> python)."""

    if hasattr(value, "item"):
        value = value.item()

    if isinstance(value, float) and not math.isfinite(value):
        return None

    return value


def _pct(numerator, denominator):

    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


# ============================================================
# SQLITE AUDIT (read-only)
# ============================================================

def read_run_database(run_dir):
    """Read this run's SQLite memory in read-only mode."""

    db_path = Path(run_dir) / "threat_memory_run.db"

    result = {
        "path": db_path.name,
        "available": db_path.exists(),
        "tables": {},
        "recovery_audit": [],
        "endpoint_healing_audit": [],
        "top_patterns": [],
    }

    if not db_path.exists():
        return result

    uri = db_path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row

    try:
        tables = [
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ]

        for table in tables:
            result["tables"][table] = conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

        if "recovery_audit" in tables:
            result["recovery_audit"] = [
                {k: row[k] for k in row.keys() if k != "metadata"}
                for row in conn.execute(
                    "SELECT * FROM recovery_audit ORDER BY id"
                )
            ]

        if "endpoint_healing_audit" in tables:
            result["endpoint_healing_audit"] = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM endpoint_healing_audit ORDER BY id"
                )
            ]

        if "threat_patterns" in tables:
            result["top_patterns"] = [
                dict(row) for row in conn.execute(
                    "SELECT pattern_id, occurrence_count, severity, "
                    "last_action, successful_containments, "
                    "failed_containments, average_confidence "
                    "FROM threat_patterns "
                    "ORDER BY occurrence_count DESC LIMIT 12"
                )
            ]
            result["repeated_patterns"] = conn.execute(
                "SELECT COUNT(*) FROM threat_patterns "
                "WHERE occurrence_count > 1"
            ).fetchone()[0]

    finally:
        conn.close()

    return result


# ============================================================
# RUN-DERIVED VIEWS
# ============================================================

def _rf_metrics(events):

    tp = sum(1 for e in events if e["true_label"] == 1 and e["prediction"] == 1)
    tn = sum(1 for e in events if e["true_label"] == 0 and e["prediction"] == 0)
    fp = sum(1 for e in events if e["true_label"] == 0 and e["prediction"] == 1)
    fn = sum(1 for e in events if e["true_label"] == 1 and e["prediction"] == 0)

    precision = _pct(tp, tp + fp)
    recall = _pct(tp, tp + fn)

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": _pct(tp + tn, len(events)),
        "precision": precision,
        "recall": recall,
        "f1": round(2 * precision * recall / (precision + recall), 2)
        if (precision + recall) else 0.0,
        "benign_recall": _pct(tn, tn + fp),
        "benign_precision": _pct(tn, tn + fn),
    }


def _risk(events):

    counts = Counter(e["initial_action"] for e in events)

    risky = {
        "ALLOW": sum(1 for e in events if e["initial_action"] == "ALLOW" and e["true_label"] == 1),
        "ALERT": sum(1 for e in events if e["initial_action"] == "ALERT" and e["true_label"] == 1),
        "BLOCK": sum(1 for e in events if e["initial_action"] == "BLOCK" and e["true_label"] == 0),
    }

    return {
        action: {
            "total": counts.get(action, 0),
            "risk": risky[action],
            "safe": counts.get(action, 0) - risky[action],
            "risk_pct": _pct(risky[action], counts.get(action, 0)),
        }
        for action in ACTIONS
    }


def _representative(events):
    """Pick real events covering each decision outcome (no invented rows)."""

    rules = [
        ("Attack contained by BLOCK", lambda e: e["true_label"] == 1 and e["initial_action"] == "BLOCK"),
        ("Benign traffic allowed", lambda e: e["true_label"] == 0 and e["initial_action"] == "ALLOW"),
        ("Attack missed by RF → ALLOW", lambda e: e["true_label"] == 1 and e["initial_action"] == "ALLOW"),
        ("Attack only alerted", lambda e: e["true_label"] == 1 and e["initial_action"] == "ALERT"),
        ("Benign alerted (unnecessary)", lambda e: e["true_label"] == 0 and e["initial_action"] == "ALERT"),
        ("Benign blocked (false block)", lambda e: e["true_label"] == 0 and e["initial_action"] == "BLOCK"),
        ("Repeated pattern, defense reused", lambda e: e["healing_action"] == "REUSE_DEFENSE"),
        ("Lower-confidence attack", lambda e: e["true_label"] == 1 and e["prediction"] == 1 and (e["confidence"] or 1) < 0.9),
    ]

    picked = []

    for label, rule in rules:
        match = next((e for e in events if rule(e)), None)
        picked.append({"case": label, "event": match})

    return picked


def _file_matrix(report):
    """Per-file state across clean -> compromised -> healed."""

    clean = (report.get("clean_state") or {}).get("files", {})
    before = (report.get("state_before") or {}).get("files", {})
    after = (report.get("state_after") or {}).get("files", {})
    checks = {c["path"]: c for c in report.get("integrity_checks", [])}

    rows = []

    for rel in sorted(set(clean) | set(before) | set(after)):

        if rel not in clean:
            compromised = "INJECTED"
        elif rel not in before:
            compromised = "DELETED"
        elif before[rel] != clean[rel]:
            compromised = "MODIFIED"
        else:
            compromised = "UNCHANGED"

        if rel not in clean:
            healed = "QUARANTINED" if rel not in after else "STILL PRESENT"
        elif rel in checks and checks[rel]["passed"]:
            healed = "VERIFIED"
        else:
            healed = "FAILED"

        rows.append({
            "path": rel,
            "clean_sha256": clean.get(rel),
            "compromised_sha256": before.get(rel),
            "healed_sha256": after.get(rel),
            "compromised_state": compromised,
            "healed_state": healed,
        })

    return rows


def _compact_endpoint(report):

    keys = [
        "incident_id", "host_id", "scenario", "scenario_description",
        "mode", "recovery_status", "verified", "simulated_attack",
        "detected", "quarantine_actions", "persistence_removed",
        "restoration_actions", "integrity_checks", "integrity_summary",
        "state_comparison", "failure_reasons", "baseline_trust_problems",
        "trigger_incident", "trigger_note", "endpoint_verification",
        "final_healing_decision", "report_path", "started_at",
        "finished_at",
    ]

    data = {key: report.get(key) for key in keys}
    data["file_matrix"] = _file_matrix(report)
    data["persistence_clean"] = [
        e.get("name") for e in (report.get("clean_state") or {}).get("persistence_entries", [])
    ]
    data["persistence_compromised"] = [
        e.get("name") for e in (report.get("state_before") or {}).get("persistence_entries", [])
    ]
    data["persistence_healed"] = [
        e.get("name") for e in (report.get("state_after") or {}).get("persistence_entries", [])
    ]

    return data


def _load_json(path):

    path = Path(path)

    if not path.exists():
        return None

    return json.loads(path.read_text(encoding="utf-8"))


def build_run_data(run_id, run_dir, summary, events_df, q_table,
                   endpoint_results):

    raw = events_df.to_dict(orient="records")

    events = [
        {v2: _clean(row.get(src)) for v2, src in V2_EVENT_MAP.items()}
        for row in raw
    ]

    for event in events:
        for key in ("recovery_action", "pattern_id", "recommended_action"):
            if event[key] is None:
                event[key] = ""

    policy = []
    for state in sorted(q_table):
        q = q_table[state]
        policy.append({
            "state": str(state),
            "best_action": max(ACTIONS, key=lambda a: q[a]),
            "q_values": [round(float(q[a]), 2) for a in ACTIONS],
        })

    cumulative, curve = 0, []
    for index, event in enumerate(events):
        cumulative += event["reward"] or 0
        if index % 100 == 0 or index == len(events) - 1:
            curve.append({"step": index, "reward": cumulative})

    severity = Counter(e["severity"] for e in events)
    patterns = Counter(e["pattern_status"] for e in events)

    step_log = [e for e in events if e["step"] % 300 == 0]

    database = read_run_database(run_dir)

    view = {
        "rf": _rf_metrics(events),
        "actions": {a: sum(1 for e in events if e["initial_action"] == a) for a in ACTIONS},
        "risk": _risk(events),
        "severity": {s: severity.get(s, 0) for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "severity_pct": {s: _pct(severity.get(s, 0), len(events)) for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "patterns": {p: patterns.get(p, 0) for p in ["NEW", "KNOWN", "REPEATED", "NOT_ANALYZED"]},
        "reward_curve": curve,
        "step_log": step_log,
        "representative": _representative(events),
        "unique_states": len({e["rl_state"] for e in events}),
        "healing_actions": dict(Counter(e["healing_action"] for e in events)),
    }

    return {
        "run_id": run_id,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "generated_from": {
            "run_folder": f"runs/{run_id}/",
            "events_file": "security_events.csv",
            "summary_file": "pipeline_summary.csv / pipeline_summary.json",
            "endpoint_reports": "endpoint_sim/<HOST>/reports/",
            "database": "threat_memory_run.db",
        },
        "summary": {k: _clean(v) for k, v in summary.items()},
        "events": events,
        "policy": policy,
        "view": view,
        "database": database,
        "endpoint_healing": [_compact_endpoint(r) for r in endpoint_results],
        "apt_campaign": _load_json(Path(run_dir) / "apt_sim" / "campaign_report.json"),
        "charts": [c for c in CHARTS if (Path(run_dir) / c).exists()],
        "scope": {
            "network_response": "SIMULATED (no real firewall rules applied)",
            "recovery": "OFFLINE ORACLE-ASSISTED (ground truth after the initial action)",
            "endpoint_healing": (
                "CONTROLLED ENDPOINT HEALING SIMULATION: real file quarantine, "
                "restoration and SHA-256 verification inside an isolated "
                "project folder. Not real Windows remediation."
            ),
            "not_implemented": [
                "Live firewall enforcement",
                "Live endpoint isolation",
                "Live network telemetry verification",
                "Real Windows endpoint remediation",
            ],
        },
    }


def export_dashboard(run_dir, run_data):

    run_dir = Path(run_dir)

    data_path = cfg.assert_inside(run_dir / "dashboard_data.js", run_dir)
    html_path = cfg.assert_inside(run_dir / "dashboard.html", run_dir)

    with open(data_path, "w", encoding="utf-8") as handle:
        handle.write("window.RUN_DATA = ")
        json.dump(run_data, handle, default=str)
        handle.write(";\n")

    shutil.copyfile(cfg.DASHBOARD_TEMPLATE, html_path)

    # Bundle Chart.js next to the dashboard so it works fully offline
    if cfg.CHART_JS.exists():
        shutil.copyfile(
            cfg.CHART_JS,
            cfg.assert_inside(run_dir / "chart.umd.js", run_dir),
        )

    if cfg.FONTS_DIR.exists():
        shutil.copytree(
            cfg.FONTS_DIR,
            cfg.assert_inside(run_dir / "fonts", run_dir),
            dirs_exist_ok=True,
        )

    return html_path


def validate_dashboard(html_path, run_id):
    """Confirm the dashboard files exist and belong to this run."""

    html_path = Path(html_path)
    data_path = html_path.parent / "dashboard_data.js"

    if not html_path.exists() or not data_path.exists():
        return False, "dashboard files missing"

    text = data_path.read_text(encoding="utf-8")

    if not text.startswith("window.RUN_DATA = "):
        return False, "dashboard_data.js malformed"

    data = json.loads(text[len("window.RUN_DATA = "):].rstrip().rstrip(";"))

    if data.get("run_id") != run_id:
        return False, "dashboard data run_id mismatch"

    foreign = [
        e.get("event_id") for e in data.get("events", [])
        if run_id not in str(e.get("event_id"))
    ]

    if foreign:
        return False, f"{len(foreign)} events belong to another run"

    return True, f"{len(data.get('events', []))} events for run {run_id}"


def regenerate(run_dir):
    """
    Rebuild the dashboard for an EXISTING run folder from its saved
    outputs (no pipeline execution). Used for dashboard development.
    """

    import pandas as pd
    import joblib

    run_dir = Path(run_dir).resolve()
    run_id = run_dir.name

    summary = json.loads((run_dir / "pipeline_summary.json").read_text(encoding="utf-8"))
    events_df = pd.read_csv(run_dir / "security_events.csv")
    q_table = joblib.load(cfg.Q_TABLE_FILE)

    reports = []
    for path in sorted((run_dir / "endpoint_sim").glob("HOST-*/reports/healing_report_*.json")):
        reports.append(json.loads(path.read_text(encoding="utf-8")))

    run_data = build_run_data(run_id, run_dir, summary, events_df, q_table, reports)
    return export_dashboard(run_dir, run_data), run_id


CHROME_CANDIDATES = [
    Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
    / "Google/Chrome/Application/chrome.exe",
    Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
    / "Google/Chrome/Application/chrome.exe",
    Path(os.environ.get("LOCALAPPDATA", ""))
    / "Google/Chrome/Application/chrome.exe",
]


def open_dashboard(html_path):
    """Open in Chrome if installed, otherwise the default browser."""

    uri = Path(html_path).resolve().as_uri()

    for chrome in CHROME_CANDIDATES:
        if chrome.is_file():
            subprocess.Popen([str(chrome), uri])
            return f"Chrome ({chrome})"

    webbrowser.open(uri)
    return "default browser"


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:
        print("Usage: python dashboard_export.py runs/<RUN_ID> [--open]")
        sys.exit(1)

    path, rid = regenerate(sys.argv[1])
    ok, detail = validate_dashboard(path, rid)
    print(f"Dashboard: {path}\nValidation: {'OK' if ok else 'FAILED'} ({detail})")

    if ok and "--open" in sys.argv:
        print("Opened in", open_dashboard(path))
