"""
Unit tests for controlled endpoint healing and its integration.

Run from the project root:
    python -B -m unittest discover -s tests -v

All tests use temporary folders/databases; no project artefact is touched.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from endpoint_healing import (  # noqa: E402
    MALICIOUS_DROP,
    MALICIOUS_PERSISTENCE,
    SCENARIOS,
    EndpointHealer,
    SimulatedEndpoint,
    run_demonstration,
    run_endpoint_scenario,
    sha256_file,
    simulate_compromise,
)
from response_verifier import ResponseVerifier  # noqa: E402
from self_healing_engine import SelfHealingEngine  # noqa: E402
from threat_memory import ThreatMemory  # noqa: E402


class EndpointHealingTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make_endpoint(self, host="HOST-T"):
        ep = SimulatedEndpoint(self.base / host, host)
        ep.provision()
        ep.snapshot_baseline()
        return ep

    # ---------------------------------------------------------------

    def test_baseline_manifest_matches_live_files(self):
        ep = self.make_endpoint()
        manifest = ep.load_manifest()
        self.assertEqual(len(manifest), 5)
        for rel, digest in manifest.items():
            self.assertEqual(sha256_file(ep.live / rel), digest)

    def test_compromise_really_changes_endpoint(self):
        ep = self.make_endpoint()
        before = ep.capture_state()
        simulate_compromise(ep)
        after = ep.capture_state()
        self.assertIn(MALICIOUS_DROP, after["files"])
        self.assertNotIn("files/web/index.html", after["files"])
        self.assertNotEqual(
            before["files"]["config/app_config.json"],
            after["files"]["config/app_config.json"],
        )
        names = [e["name"] for e in after["persistence_entries"]]
        self.assertIn(MALICIOUS_PERSISTENCE["name"], names)

    def test_successful_healing_restores_exact_baseline(self):
        ep = self.make_endpoint()
        clean = ep.capture_state()["files"]
        simulate_compromise(ep)
        report = EndpointHealer(ep).heal("INC-OK")

        self.assertEqual(report["recovery_status"], "HEALED_VERIFIED")
        self.assertTrue(report["verified"])
        self.assertEqual(report["failure_reasons"], [])

        # Independent re-check: live files are byte-identical to the clean state
        self.assertEqual(ep.capture_state()["files"], clean)

        # Quarantined artefact moved, not deleted
        q = report["quarantine_actions"][0]
        self.assertTrue((ep.root / q["quarantine_path"]).exists())
        self.assertFalse((ep.live / MALICIOUS_DROP).exists())

        self.assertEqual(report["persistence_removed"], [MALICIOUS_PERSISTENCE["name"]])
        restored = {a["path"] for a in report["restoration_actions"] if a["restored"]}
        self.assertEqual(
            restored,
            {"config/app_config.json", "files/payroll_report.txt", "files/web/index.html"},
        )
        self.assertTrue((ep.reports / "healing_report_INC-OK.json").exists())

    def test_poisoned_baseline_reports_incomplete_recovery(self):
        ep = self.make_endpoint()
        simulate_compromise(ep, poison_baseline=True)
        report = EndpointHealer(ep).heal("INC-FAIL")

        self.assertEqual(report["recovery_status"], "HEALING_INCOMPLETE")
        self.assertFalse(report["verified"])
        failed = [c["path"] for c in report["integrity_checks"] if not c["passed"]]
        self.assertEqual(failed, ["files/payroll_report.txt"])
        refused = [a for a in report["restoration_actions"] if not a["restored"]]
        self.assertEqual(refused[0]["path"], "files/payroll_report.txt")
        # The untrusted copy must NOT have been written to the live file
        self.assertNotIn(
            "backup-also-corrupted",
            (ep.live / "files/payroll_report.txt").read_text(encoding="utf-8"),
        )
        self.assertTrue(report["failure_reasons"])

    def test_tampered_manifest_blocks_healing(self):
        ep = self.make_endpoint()
        simulate_compromise(ep)
        manifest = ep.load_manifest()
        manifest["files/payroll_report.txt"] = "0" * 64
        ep.manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
        report = EndpointHealer(ep).heal("INC-MANIFEST")
        self.assertEqual(report["recovery_status"], "HEALING_INCOMPLETE")
        self.assertIn("Baseline manifest hash mismatch (tampered)", report["failure_reasons"])
        # Nothing was "fixed" on the strength of an untrusted manifest
        self.assertTrue((ep.live / MALICIOUS_DROP).exists())

    def test_path_guard_blocks_writes_outside_sandbox(self):
        ep = self.make_endpoint()
        with self.assertRaises(PermissionError):
            ep.write_text(self.base / "outside.txt", "x")
        with self.assertRaises(PermissionError):
            ep.write_text(ep.live / ".." / ".." / "escape.txt", "x")
        self.assertFalse((self.base / "outside.txt").exists())

    # ---------------------------------------------------------------

    def test_verifier_endpoint_mode_uses_hash_evidence(self):
        v = ResponseVerifier()
        ok = run_endpoint_scenario(self.base, SCENARIOS[0], "V-OK")
        bad = run_endpoint_scenario(self.base, SCENARIOS[1], "V-BAD")
        r_ok = v.verify("ENDPOINT_RESTORE", "x", 1, "HIGH",
                        verification_mode="ENDPOINT_INTEGRITY", observed_outcome=ok)
        r_bad = v.verify("ENDPOINT_RESTORE", "x", 1, "HIGH",
                         verification_mode="ENDPOINT_INTEGRITY", observed_outcome=bad)
        r_none = v.verify("ENDPOINT_RESTORE", "x", 1, "HIGH",
                          verification_mode="ENDPOINT_INTEGRITY", observed_outcome=None)
        self.assertEqual(r_ok["verification_status"], "SUCCESS")
        self.assertEqual(r_bad["verification_status"], "FAILED")
        self.assertTrue(r_bad["recovery_required"])
        self.assertEqual(r_none["verification_status"], "PENDING")

    def test_engine_endpoint_decisions(self):
        eng = SelfHealingEngine()
        self.assertTrue(eng.requires_endpoint_healing({"healing_action": "ESCALATE"}))
        self.assertFalse(eng.requires_endpoint_healing({"healing_action": "MAINTAIN"}))
        self.assertEqual(
            eng.assess_endpoint_healing({"verified": True})["healing_action"],
            "ENDPOINT_RESTORED",
        )
        fail = eng.assess_endpoint_healing({"verified": False, "verification_status": "FAILED"})
        self.assertEqual(fail["healing_action"], "SOC_REVIEW")
        self.assertTrue(fail["escalation_required"])

    def test_demonstration_end_to_end_with_audit(self):
        db = self.base / "audit.db"
        memory = ThreatMemory(str(db))
        incidents = [{"event_id": "EVT-X-0001", "healing_action": "ESCALATE",
                      "initial_action": "ALLOW", "healing_severity": "HIGH"}]
        results = run_demonstration(self.base / "run", "RUN-T", incidents,
                                    ResponseVerifier(), SelfHealingEngine(), memory)
        rows = memory.get_endpoint_healing_audits()
        memory.close()

        self.assertEqual([r["scenario"] for r in results],
                         ["SUCCESSFUL_HEALING", "FAILED_HEALING"])
        self.assertEqual([r["recovery_status"] for r in results],
                         ["HEALED_VERIFIED", "HEALING_INCOMPLETE"])
        self.assertEqual([r["final_healing_decision"]["healing_action"] for r in results],
                         ["ENDPOINT_RESTORED", "SOC_REVIEW"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["trigger_event_id"], "EVT-X-0001")
        self.assertEqual([r["verified"] for r in rows], [1, 0])


class DashboardExportTests(unittest.TestCase):

    def test_export_and_validate(self):
        from dashboard_export import build_run_data, export_dashboard, validate_dashboard

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            events = pd.DataFrame([
                {"step": 0, "event_id": "EVT-RUN-D-0000", "true_label": 1, "prediction": 1,
                 "confidence": float("nan"), "action": "BLOCK", "reward": 10,
                 "severity": "CRITICAL", "healing_action": "MAINTAIN"},
                {"step": 1, "event_id": "EVT-RUN-D-0001", "true_label": 1, "prediction": 0,
                 "confidence": 1.0, "action": "ALLOW", "reward": -15,
                 "severity": "LOW", "healing_action": "ESCALATE"},
            ])
            data = build_run_data("RUN-D", run_dir, {"run_id": "RUN-D", "total_samples": 2},
                                  events, {(1, 9): {"ALLOW": -1.0, "ALERT": 0.5, "BLOCK": 9.0}}, [])
            html = export_dashboard(run_dir, data)
            ok, detail = validate_dashboard(html, "RUN-D")
            self.assertTrue(ok, detail)
            self.assertFalse(validate_dashboard(html, "OTHER-RUN")[0])
            self.assertEqual(data["policy"][0]["best_action"], "BLOCK")
            self.assertIsNone(data["events"][0]["confidence"])  # NaN made JSON-safe
            # V2 dashboard schema + run-derived views
            self.assertEqual(data["events"][1]["initial_action"], "ALLOW")
            self.assertEqual(data["view"]["actions"], {"ALLOW": 1, "ALERT": 0, "BLOCK": 1})
            self.assertEqual(data["view"]["risk"]["ALLOW"]["risk"], 1)  # missed attack
            self.assertEqual(data["view"]["rf"]["fn"], 1)
            self.assertEqual(data["view"]["reward_curve"][-1]["reward"], -5)
            self.assertFalse(data["database"]["available"])  # no DB -> reported, not faked

    def test_validate_rejects_foreign_events(self):
        from dashboard_export import build_run_data, export_dashboard, validate_dashboard

        with tempfile.TemporaryDirectory() as tmp:
            events = pd.DataFrame([{"step": 0, "event_id": "HOLDOUT-OLD-0000",
                                    "true_label": 0, "prediction": 0, "confidence": 1.0,
                                    "action": "ALLOW", "reward": 5}])
            data = build_run_data("RUN-X", Path(tmp), {}, events, {}, [])
            html = export_dashboard(Path(tmp), data)
            ok, detail = validate_dashboard(html, "RUN-X")
            self.assertFalse(ok)
            self.assertIn("another run", detail)

    def test_template_has_no_hardcoded_run_values(self):
        import project_config as cfg
        text = cfg.DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn('src="dashboard_data.js"', text)
        self.assertIn('data-pg="endpoint"', text)
        for stale in ["HOLDOUT-2026", "8,513", "const EVENTS=[{"]:
            self.assertNotIn(stale, text)


if __name__ == "__main__":
    unittest.main()
