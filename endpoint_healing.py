"""
Controlled endpoint healing (simulated endpoint).

This module gives the project a demonstrable, verifiable recovery of a
TARGET DEVICE after an attack, inside an isolated project-owned sandbox:

    known-good baseline  ->  simulated compromise  ->  detection
    ->  quarantine  ->  restoration from baseline  ->  persistence removal
    ->  SHA-256 integrity verification  ->  before/after comparison
    ->  audit report

SCOPE AND SAFETY
----------------
* The "endpoint" is a folder (e.g. runs/<RUN_ID>/endpoint_sim/HOST-01).
* All files are inert dummy text/JSON. Nothing is executed.
* "Persistence" is a JSON list that imitates startup entries. The real
  Windows registry, startup folders, services and firewall are NEVER read
  or modified.
* Every write goes through a path guard that refuses any path outside
  the endpoint's root folder.
* Healing success is decided ONLY by re-hashing the endpoint and
  comparing it with the trusted baseline manifest. It is never assumed.

This is controlled endpoint-healing SIMULATION, not real Windows
remediation and not live network isolation.
"""

import base64
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path


# ============================================================
# HELPERS
# ============================================================

def sha256_file(path):

    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_bytes(data):

    return hashlib.sha256(data).hexdigest()


def _now():

    return datetime.now().isoformat(timespec="seconds")


PERSISTENCE_FILE = "persistence/startup_entries.json"


# ============================================================
# SIMULATED ENDPOINT
# ============================================================

class SimulatedEndpoint:
    """An isolated, folder-based stand-in for a protected host."""

    def __init__(self, root, host_id="HOST-01"):

        self.host_id = host_id
        self.root = Path(root).resolve()
        self.live = self.root / "live"
        self.baseline_store = self.root / "baseline" / "store"
        self.manifest_file = self.root / "baseline" / "manifest.json"
        self.manifest_hash_file = self.root / "baseline" / "manifest.sha256"
        self.quarantine = self.root / "quarantine"
        self.reports = self.root / "reports"

    # --------------------------------------------------------
    # PATH GUARD
    # --------------------------------------------------------

    def safe(self, path):

        resolved = Path(path).resolve()

        if resolved != self.root and self.root not in resolved.parents:
            raise PermissionError(
                f"Endpoint sandbox violation: {resolved} is outside "
                f"{self.root}"
            )

        return resolved

    def write_text(self, path, text):

        path = self.safe(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_json(self, path, data):

        self.write_text(path, json.dumps(data, indent=2, sort_keys=True))

    # --------------------------------------------------------
    # PROVISION KNOWN-GOOD STATE
    # --------------------------------------------------------

    def provision(self):
        """Create the clean endpoint content (inert dummy data)."""

        self.safe(self.root).mkdir(parents=True, exist_ok=True)

        self.write_text(
            self.live / "files/customer_records.csv",
            "customer_id,name,region\n1001,Asha,West\n1002,Rahul,North\n"
            "1003,Meera,South\n",
        )

        self.write_text(
            self.live / "files/payroll_report.txt",
            "Quarterly payroll summary (dummy data)\n"
            "Department totals: Eng=42, Ops=17, Sales=23\n",
        )

        self.write_text(
            self.live / "files/web/index.html",
            "<html><body><h1>Internal portal (simulated)</h1>"
            "</body></html>\n",
        )

        self.write_json(
            self.live / "config/app_config.json",
            {
                "firewall_profile": "strict",
                "remote_admin_enabled": False,
                "update_server": "https://updates.internal.example",
                "audit_logging": True,
            },
        )

        self.write_json(
            self.live / PERSISTENCE_FILE,
            [
                {"name": "SecurityAgent", "command": "agent --monitor"},
                {"name": "BackupService", "command": "backup --daily"},
            ],
        )

    # --------------------------------------------------------
    # BASELINE
    # --------------------------------------------------------

    def snapshot_baseline(self):
        """Copy the clean state and record a SHA-256 manifest."""

        store = self.safe(self.baseline_store)

        if store.exists():
            shutil.rmtree(store)

        shutil.copytree(self.safe(self.live), store)

        manifest = {
            rel: sha256_file(self.live / rel)
            for rel in self.list_files(self.live)
        }

        self.write_json(self.manifest_file, manifest)

        # A separate hash of the manifest lets the healer detect a
        # tampered manifest before trusting it.
        self.write_text(
            self.manifest_hash_file,
            sha256_file(self.manifest_file),
        )

        return manifest

    # --------------------------------------------------------
    # STATE
    # --------------------------------------------------------

    @staticmethod
    def list_files(folder):

        folder = Path(folder)

        if not folder.exists():
            return []

        return sorted(
            path.relative_to(folder).as_posix()
            for path in folder.rglob("*")
            if path.is_file()
        )

    def load_manifest(self):

        return json.loads(self.manifest_file.read_text(encoding="utf-8"))

    def read_persistence(self, folder=None):

        path = Path(folder or self.live) / PERSISTENCE_FILE

        if not path.exists():
            return []

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return [{"name": "<unparseable persistence file>"}]

    def capture_state(self):
        """Hash every live file and read persistence entries."""

        return {
            "captured_at": _now(),
            "files": {
                rel: sha256_file(self.live / rel)
                for rel in self.list_files(self.live)
            },
            "persistence_entries": self.read_persistence(),
        }


# ============================================================
# ATTACK SIMULATOR (inert, sandbox only)
# ============================================================

MALICIOUS_DROP = "files/temp/svc_update_helper.ps1.txt"
MALICIOUS_PERSISTENCE = {
    "name": "WinUpdateHelper",
    "command": "powershell -w hidden files/temp/svc_update_helper.ps1",
}


def simulate_compromise(endpoint, poison_baseline=False):
    """
    Apply a scripted, inert compromise to the simulated endpoint.

    poison_baseline=True additionally tampers with the stored backup of
    one file. This models an attacker who also corrupted the recovery
    copy, and is used for the FAILED-healing demonstration.
    """

    actions = []

    # 1. Dropped artefact (dummy text, never executed)
    endpoint.write_text(
        endpoint.live / MALICIOUS_DROP,
        "SIMULATED MALICIOUS ARTIFACT - INERT TEXT FOR THE PROJECT DEMO\n"
        "beacon_interval=300; c2=203.0.113.50\n",
    )
    actions.append({"type": "DROP_FILE", "path": MALICIOUS_DROP})

    # 2. Configuration tampering
    config_path = endpoint.live / "config/app_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["remote_admin_enabled"] = True
    config["firewall_profile"] = "disabled"
    config["update_server"] = "http://203.0.113.50/updates"
    endpoint.write_json(config_path, config)
    actions.append({"type": "MODIFY_CONFIG", "path": "config/app_config.json"})

    # 3. File tampering (simulated encryption)
    payroll = endpoint.live / "files/payroll_report.txt"
    endpoint.write_text(
        payroll,
        "ENCRYPTED::"
        + base64.b64encode(payroll.read_bytes()).decode("ascii")
        + "\n",
    )
    actions.append({"type": "MODIFY_FILE", "path": "files/payroll_report.txt"})

    # 4. File deletion
    index = endpoint.safe(endpoint.live / "files/web/index.html")
    index.unlink()
    actions.append({"type": "DELETE_FILE", "path": "files/web/index.html"})

    # 5. Simulated persistence entry
    entries = endpoint.read_persistence()
    entries.append(dict(MALICIOUS_PERSISTENCE))
    endpoint.write_json(endpoint.live / PERSISTENCE_FILE, entries)
    actions.append({
        "type": "ADD_PERSISTENCE",
        "entry": MALICIOUS_PERSISTENCE["name"],
    })

    # 6. Optional: poison the backup copy (failure scenario)
    if poison_baseline:
        endpoint.write_text(
            endpoint.baseline_store / "files/payroll_report.txt",
            "ENCRYPTED::backup-also-corrupted-by-attacker\n",
        )
        actions.append({
            "type": "POISON_BASELINE_COPY",
            "path": "baseline/store/files/payroll_report.txt",
        })

    return actions


# ============================================================
# ENDPOINT HEALER
# ============================================================

class EndpointHealer:
    """Detects, quarantines, restores and verifies a simulated endpoint."""

    def __init__(self, endpoint):

        self.endpoint = endpoint

    # --------------------------------------------------------
    # BASELINE TRUST
    # --------------------------------------------------------

    def check_baseline_trust(self):

        ep = self.endpoint
        problems = []

        if not ep.manifest_file.exists() or not ep.manifest_hash_file.exists():
            return None, set(), ["Baseline manifest missing"]

        expected = ep.manifest_hash_file.read_text(encoding="utf-8").strip()

        if sha256_file(ep.manifest_file) != expected:
            return None, set(), ["Baseline manifest hash mismatch (tampered)"]

        manifest = ep.load_manifest()
        trusted = set()

        for rel, digest in manifest.items():
            stored = ep.baseline_store / rel

            if not stored.exists():
                problems.append(f"Baseline copy missing: {rel}")
            elif sha256_file(stored) != digest:
                problems.append(
                    f"Baseline copy failed integrity check: {rel}"
                )
            else:
                trusted.add(rel)

        return manifest, trusted, problems

    # --------------------------------------------------------
    # DETECTION
    # --------------------------------------------------------

    def detect(self, manifest, state):

        live_files = state["files"]

        unauthorized = sorted(set(live_files) - set(manifest))
        missing = sorted(set(manifest) - set(live_files))
        modified = sorted(
            rel for rel in set(manifest) & set(live_files)
            if live_files[rel] != manifest[rel]
        )

        baseline_names = {
            entry.get("name")
            for entry in self.endpoint.read_persistence(
                self.endpoint.baseline_store
            )
        }

        rogue_persistence = [
            entry for entry in state["persistence_entries"]
            if entry.get("name") not in baseline_names
        ]

        return {
            "unauthorized_files": unauthorized,
            "modified_files": modified,
            "missing_files": missing,
            "unauthorized_persistence": rogue_persistence,
        }

    # --------------------------------------------------------
    # HEAL
    # --------------------------------------------------------

    def heal(self, incident_id):

        ep = self.endpoint
        started = _now()

        before = ep.capture_state()
        manifest, trusted, trust_problems = self.check_baseline_trust()

        report = {
            "incident_id": incident_id,
            "host_id": ep.host_id,
            "mode": "CONTROLLED_ENDPOINT_SIMULATION",
            "started_at": started,
            "state_before": before,
            "baseline_trust_problems": trust_problems,
            "detected": None,
            "quarantine_actions": [],
            "persistence_removed": [],
            "restoration_actions": [],
            "integrity_checks": [],
            "failure_reasons": list(trust_problems),
        }

        if manifest is None:
            return self._finish(report)

        detected = self.detect(manifest, before)
        report["detected"] = detected

        # 1. Quarantine unauthorized artefacts (move, never delete)
        # Short, stable folder name (the full incident_id is kept in the
        # report). Keeps nested paths well under the Windows MAX_PATH limit.
        q_dir = ep.quarantine / (
            "q-" + hashlib.sha256(incident_id.encode("utf-8")).hexdigest()[:10]
        )
        report["quarantine_folder"] = q_dir.relative_to(ep.root).as_posix()

        for rel in detected["unauthorized_files"]:
            source = ep.safe(ep.live / rel)
            target = ep.safe(q_dir / (rel.replace("/", "__") + ".quarantined"))
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = sha256_file(source)
            shutil.move(str(source), str(target))
            report["quarantine_actions"].append({
                "original_path": rel,
                "quarantine_path": target.relative_to(ep.root).as_posix(),
                "sha256": digest,
                "moved": not source.exists() and target.exists(),
            })

        # 2. Remove simulated persistence entries not in the baseline
        if detected["unauthorized_persistence"]:
            rogue = {e.get("name") for e in detected["unauthorized_persistence"]}
            kept = [e for e in ep.read_persistence() if e.get("name") not in rogue]
            ep.write_json(ep.live / PERSISTENCE_FILE, kept)
            report["persistence_removed"] = sorted(rogue)

        # 3. Restore modified / missing files from TRUSTED baseline only
        after_persistence = ep.capture_state()["files"]

        for rel in sorted(set(manifest)):
            if after_persistence.get(rel) == manifest[rel]:
                continue

            if rel not in trusted:
                report["restoration_actions"].append({
                    "path": rel,
                    "restored": False,
                    "reason": "Baseline copy untrusted; restore refused",
                })
                report["failure_reasons"].append(
                    f"Could not restore {rel}: no trusted baseline copy"
                )
                continue

            target = ep.safe(ep.live / rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ep.baseline_store / rel, target)
            report["restoration_actions"].append({
                "path": rel,
                "restored": True,
                "source": f"baseline/store/{rel}",
                "previous_state": (
                    "MISSING" if rel not in after_persistence else "MODIFIED"
                ),
            })

        # 4. Verify by re-hashing everything
        after = ep.capture_state()
        report["state_after"] = after

        for rel, digest in manifest.items():
            actual = after["files"].get(rel)
            report["integrity_checks"].append({
                "path": rel,
                "expected_sha256": digest,
                "actual_sha256": actual,
                "passed": actual == digest,
            })

        leftovers = sorted(set(after["files"]) - set(manifest))

        if leftovers:
            report["failure_reasons"].append(
                f"Unauthorized files still present: {leftovers}"
            )

        for check in report["integrity_checks"]:
            if not check["passed"]:
                report["failure_reasons"].append(
                    f"Integrity check failed: {check['path']}"
                )

        report["unauthorized_files_remaining"] = leftovers

        return self._finish(report, before, after)

    # --------------------------------------------------------
    # FINISH
    # --------------------------------------------------------

    def _finish(self, report, before=None, after=None):

        ep = self.endpoint

        checks = report["integrity_checks"]
        passed = sum(1 for c in checks if c["passed"])

        healed = (
            bool(checks)
            and passed == len(checks)
            and not report.get("unauthorized_files_remaining")
            and not report["failure_reasons"]
        )

        report["integrity_summary"] = {
            "files_checked": len(checks),
            "files_passed": passed,
            "files_failed": len(checks) - passed,
        }

        if before is not None and after is not None:
            report["state_comparison"] = compare_states(before, after)

        report["recovery_status"] = (
            "HEALED_VERIFIED" if healed else "HEALING_INCOMPLETE"
        )
        report["verified"] = healed
        report["finished_at"] = _now()

        # De-duplicate failure reasons, keep order
        seen = []
        for reason in report["failure_reasons"]:
            if reason not in seen:
                seen.append(reason)
        report["failure_reasons"] = seen

        report_path = ep.reports / f"healing_report_{report['incident_id']}.json"
        ep.write_json(report_path, report)
        report["report_path"] = report_path.relative_to(ep.root).as_posix()

        return report


def compare_states(before, after):

    b, a = before["files"], after["files"]

    return {
        "removed_files": sorted(set(b) - set(a)),
        "added_files": sorted(set(a) - set(b)),
        "changed_files": sorted(
            rel for rel in set(a) & set(b) if a[rel] != b[rel]
        ),
        "persistence_before": [e.get("name") for e in before["persistence_entries"]],
        "persistence_after": [e.get("name") for e in after["persistence_entries"]],
    }


# ============================================================
# DEMONSTRATION (used by pipeline.py)
# ============================================================

SCENARIOS = [
    {
        "scenario": "SUCCESSFUL_HEALING",
        "host_id": "HOST-01",
        "poison_baseline": False,
        "description": (
            "Compromise with a dropped artefact, config tampering, file "
            "encryption, file deletion and a persistence entry. The "
            "baseline backup is intact."
        ),
    },
    {
        "scenario": "FAILED_HEALING",
        "host_id": "HOST-02",
        "poison_baseline": True,
        "description": (
            "Same compromise, but the attacker also corrupted the backup "
            "copy of payroll_report.txt. The healer must refuse the "
            "untrusted copy and report incomplete recovery."
        ),
    },
]


def run_endpoint_scenario(base_dir, scenario, incident_id):

    endpoint = SimulatedEndpoint(
        Path(base_dir) / scenario["host_id"],
        scenario["host_id"],
    )

    endpoint.provision()
    clean_state = endpoint.capture_state()
    endpoint.snapshot_baseline()

    attack = simulate_compromise(
        endpoint,
        poison_baseline=scenario["poison_baseline"],
    )

    report = EndpointHealer(endpoint).heal(incident_id)

    report["scenario"] = scenario["scenario"]
    report["scenario_description"] = scenario["description"]
    report["clean_state"] = clean_state
    report["simulated_attack"] = attack

    return report


def run_demonstration(
    run_dir,
    run_id,
    incidents,
    verifier,
    engine,
    memory=None,
):
    """
    Run the successful and failed endpoint-healing scenarios.

    Each scenario is triggered by a real recovery incident from the
    current pipeline run (an attack the self-healing engine escalated).
    The incident is MAPPED onto a simulated host because CIC-IDS2017
    flows do not identify a real endpoint.

    Flow per scenario:
        SelfHealingEngine.requires_endpoint_healing(incident)
        -> EndpointHealer.heal()                (real file operations)
        -> ResponseVerifier(ENDPOINT_INTEGRITY)  (SHA-256 evidence)
        -> SelfHealingEngine.assess_endpoint_healing()
        -> ThreatMemory.store_endpoint_healing() (SQLite audit)
    """

    base = Path(run_dir) / "endpoint_sim"

    triggers = [
        inc for inc in incidents
        if engine.requires_endpoint_healing(inc)
    ]

    results = []

    for index, scenario in enumerate(SCENARIOS):

        trigger = triggers[index % len(triggers)] if triggers else None

        incident_id = f"EPH-{run_id}-{scenario['host_id']}"

        report = run_endpoint_scenario(base, scenario, incident_id)

        verification = verifier.verify(
            action="ENDPOINT_RESTORE",
            response=report["recovery_status"],
            prediction=1,
            severity=(trigger or {}).get("healing_severity", "HIGH"),
            verification_mode="ENDPOINT_INTEGRITY",
            observed_outcome=report,
        )

        final = engine.assess_endpoint_healing(verification)

        report["trigger_incident"] = trigger
        report["trigger_note"] = (
            "Triggered by a recovery incident from this pipeline run, "
            "mapped onto a simulated host."
            if trigger
            else
            "This run produced no escalated recovery incident; the "
            "scenario ran as a standalone demonstration."
        )
        report["endpoint_verification"] = verification
        report["final_healing_decision"] = final

        # Re-save the report with the integration results
        endpoint = SimulatedEndpoint(base / scenario["host_id"], scenario["host_id"])
        endpoint.write_json(endpoint.root / report["report_path"], report)

        if memory is not None:
            memory.store_endpoint_healing(
                run_id=run_id,
                trigger_event_id=(trigger or {}).get("event_id"),
                report=report,
                final_healing_action=final["healing_action"],
            )

        results.append(report)

    return results


if __name__ == "__main__":

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        for sc in SCENARIOS:
            r = run_endpoint_scenario(tmp, sc, f"DEMO-{sc['host_id']}")
            print(sc["scenario"], "->", r["recovery_status"],
                  r["integrity_summary"], r["failure_reasons"])
