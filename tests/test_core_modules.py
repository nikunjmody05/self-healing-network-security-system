"""
Consolidated, NON-DESTRUCTIVE tests for the core modules.

Ports the legacy scripts (test_response_verifier.py, test_self_healing_engine.py,
test_pattern_engine.py, test_threat_memory.py, test_threat_verification.py)
to unittest. Every database lives in a temporary folder, so no project
database is created, reused or deleted. The legacy scripts are kept unchanged
for history.

    python -B -m unittest discover -s tests -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

import project_config as cfg  # noqa: E402
from pattern_engine import PatternEngine  # noqa: E402
from response_engine import ResponseEngine  # noqa: E402
from response_verifier import ResponseVerifier  # noqa: E402
from rl_agent import RLAgent, get_reward  # noqa: E402
from self_healing_engine import SelfHealingEngine  # noqa: E402
from threat_assesment import ThreatAssessment  # noqa: E402
from threat_memory import ThreatMemory  # noqa: E402


class TempDB(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memory = ThreatMemory(str(Path(self.tmp.name) / "test.db"))

    def tearDown(self):
        self.memory.close()
        self.tmp.cleanup()


# ======================================================================
# RESPONSE VERIFIER (port of test_response_verifier.py, 10 cases)
# ======================================================================

class ResponseVerifierTests(unittest.TestCase):

    def setUp(self):
        self.v = ResponseVerifier()

    def check(self, expected, **kwargs):
        result = self.v.verify(**kwargs)
        for key, value in expected.items():
            self.assertEqual(result[key], value, (key, result))

    def test_01_attack_block(self):
        self.check({"verified": True, "verification_status": "SUCCESS", "recovery_required": False},
                   action="BLOCK", response="TRAFFIC BLOCKED", prediction=1, severity="CRITICAL")

    def test_02_benign_allow(self):
        self.check({"verified": True, "verification_status": "SUCCESS"},
                   action="ALLOW", response="TRAFFIC ALLOWED", prediction=0, severity="LOW")

    def test_03_alert(self):
        self.check({"verified": True, "verification_status": "SUCCESS"},
                   action="ALERT", response="SECURITY ALERT GENERATED", prediction=1, severity="HIGH")

    def test_04_dangerous_allow(self):
        self.check({"verified": False, "verification_status": "FAILED", "recovery_required": True},
                   action="ALLOW", response="TRAFFIC ALLOWED", prediction=1, severity="CRITICAL")

    def test_05_failed_block(self):
        self.check({"verified": False, "verification_status": "FAILED", "recovery_required": True},
                   action="BLOCK", response="BLOCK FAILED", prediction=1, severity="CRITICAL")

    def test_06_live_without_evidence_is_pending(self):
        self.check({"verified": False, "verification_status": "PENDING"},
                   action="BLOCK", response="TRAFFIC BLOCKED", prediction=1, severity="CRITICAL",
                   verification_mode="LIVE", observed_outcome=None)

    def test_07_true_attack_block(self):
        self.check({"verified": True, "containment_success": True, "recovery_required": False},
                   action="BLOCK", response="TRAFFIC BLOCKED", prediction=1, severity="CRITICAL", true_label=1)

    def test_08_false_negative_allowed(self):
        self.check({"verified": False, "containment_success": False, "recovery_required": True},
                   action="ALLOW", response="TRAFFIC ALLOWED", prediction=0, severity="LOW", true_label=1)

    def test_09_attack_alerted_not_contained(self):
        self.check({"verified": True, "containment_success": False, "recovery_required": True},
                   action="ALERT", response="SECURITY ALERT GENERATED", prediction=1, severity="HIGH", true_label=1)

    def test_10_benign_false_block(self):
        self.check({"verified": False, "containment_success": False, "verification_status": "FALSE_BLOCK"},
                   action="BLOCK", response="TRAFFIC BLOCKED", prediction=1, severity="CRITICAL", true_label=0)


# ======================================================================
# SELF-HEALING ENGINE (port of test_self_healing_engine.py, 8 cases)
# ======================================================================

class SelfHealingEngineTests(unittest.TestCase):

    def setUp(self):
        self.e = SelfHealingEngine()

    def heal(self, **kwargs):
        return self.e.heal(**kwargs)

    OK = {"verified": True, "verification_status": "SUCCESS", "recovery_required": False}
    FAIL = {"verified": False, "verification_status": "FAILED", "recovery_required": True}

    def test_1_verified_new_threat(self):
        r = self.heal(prediction=1, severity="CRITICAL", current_action="BLOCK", verification_result=self.OK)
        self.assertEqual((r["healing_status"], r["healing_action"], r["recommended_action"]),
                         ("STABLE", "MAINTAIN", "BLOCK"))

    def test_2_repeated_with_prior_success(self):
        r = self.heal(prediction=1, severity="CRITICAL", current_action="BLOCK", verification_result=self.OK,
                      pattern_status="REPEATED", occurrence_count=8, previous_action="BLOCK",
                      previous_successful_containments=3)
        self.assertEqual((r["healing_action"], r["policy_update"]), ("REUSE_DEFENSE", "REINFORCE_EXISTING_RESPONSE"))

    def test_3_critical_allowed(self):
        r = self.heal(prediction=1, severity="CRITICAL", current_action="ALLOW", verification_result=self.FAIL)
        self.assertEqual((r["healing_status"], r["recommended_action"], r["escalation_required"]),
                         ("RECOVERY_REQUIRED", "BLOCK", True))

    def test_4_medium_allowed(self):
        r = self.heal(prediction=1, severity="MEDIUM", current_action="ALLOW", verification_result=self.FAIL)
        self.assertEqual(r["recommended_action"], "ALERT")

    def test_5_alert_failed(self):
        r = self.heal(prediction=1, severity="HIGH", current_action="ALERT", verification_result=self.FAIL)
        self.assertEqual((r["recommended_action"], r["escalation_required"]), ("BLOCK", True))

    def test_6_block_failed_recommends_isolate(self):
        r = self.heal(prediction=1, severity="CRITICAL", current_action="BLOCK", verification_result=self.FAIL)
        self.assertEqual((r["healing_action"], r["recommended_action"]), ("ISOLATE", "ISOLATE"))

    def test_7_live_pending(self):
        r = self.heal(prediction=1, severity="CRITICAL", current_action="BLOCK",
                      verification_result={"verified": False, "verification_status": "PENDING", "recovery_required": False})
        self.assertEqual((r["healing_status"], r["healing_action"], r["escalation_required"]),
                         ("MONITORING", "WAIT_FOR_VERIFICATION", False))

    def test_8_verified_alert_still_uncontained(self):
        r = self.heal(prediction=1, severity="HIGH", current_action="ALERT",
                      verification_result={"verified": True, "verification_status": "SUCCESS",
                                           "containment_success": False, "recovery_required": True})
        self.assertEqual((r["healing_status"], r["recommended_action"]), ("RECOVERY_REQUIRED", "BLOCK"))

    def test_9_isolate_is_not_executable_by_response_engine(self):
        # Documents the scope boundary: ISOLATE is a recommendation only.
        self.assertEqual(ResponseEngine().execute("ISOLATE", "CRITICAL")["status"], "ERROR")


# ======================================================================
# PATTERN ENGINE (port of test_pattern_engine.py)
# ======================================================================

FEATURES = {
    "Flow Duration": 850000, "Flow Packets/s": 145, "Flow Bytes/s": 12500,
    "Fwd Packet Length Mean": 420, "Bwd Packet Length Mean": 380,
    "Flow IAT Mean": 54000, "Flow IAT Std": 21000, "Packet Length Variance": 8500,
}


class PatternEngineTests(TempDB):

    def test_new_known_repeated_and_distinct(self):
        engine = PatternEngine(self.memory)
        r1 = engine.analyze(1, 0.98, 98, "CRITICAL", FEATURES)
        self.memory.create_pattern(r1["pattern_id"], r1["fingerprint"], 1, 0.98, 98, "CRITICAL",
                                   "BLOCK", "TRAFFIC BLOCKED", containment_success=True)
        r2 = engine.analyze(1, 0.98, 98, "CRITICAL", FEATURES)
        self.memory.update_pattern(r2["pattern_id"], 0.97, 97, "CRITICAL", "BLOCK",
                                   "TRAFFIC BLOCKED", containment_success=True)
        r3 = engine.analyze(1, 0.98, 98, "CRITICAL", FEATURES)
        other = dict(FEATURES, **{"Flow Duration": 200000, "Flow Packets/s": 40, "Flow Bytes/s": 3500,
                                  "Fwd Packet Length Mean": 120, "Bwd Packet Length Mean": 90})
        r4 = engine.analyze(1, 0.82, 82, "CRITICAL", other)

        self.assertEqual([r1["pattern_status"], r2["pattern_status"], r3["pattern_status"]],
                         ["NEW", "KNOWN", "REPEATED"])
        self.assertEqual(r1["fingerprint"], r3["fingerprint"])
        self.assertNotEqual(r1["fingerprint"], r4["fingerprint"])
        self.assertEqual(r3["previous_successful_containments"], 2)

    def test_fingerprint_is_deterministic(self):
        engine = PatternEngine(self.memory)
        a = engine.analyze(1, 0.9, 90, "CRITICAL", FEATURES)["fingerprint"]
        b = engine.analyze(1, 0.9, 90, "CRITICAL", FEATURES)["fingerprint"]
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)


# ======================================================================
# THREAT MEMORY (ports of test_threat_memory.py + test_threat_verification.py)
# ======================================================================

class ThreatMemoryTests(TempDB):

    def test_store_retrieve_and_repeat(self):
        m = self.memory
        m.create_pattern("PAT-0001", "FP-1", 1, 0.98, 98.0, "CRITICAL", "BLOCK", "TRAFFIC BLOCKED", True)
        m.store_event("EVT-1", 1, 0.98, 98.0, "CRITICAL", (1, 9), "BLOCK", "TRAFFIC BLOCKED", True,
                      "FP-1", pattern_id="PAT-0001", source_ip="192.168.1.50", metadata={"test": True})
        event = m.get_event("EVT-1")
        self.assertEqual((event["rl_state"], event["source_ip"]), ("(1, 9)", "192.168.1.50"))
        self.assertEqual(m.get_pattern_by_fingerprint("FP-1")["pattern_id"], "PAT-0001")
        updated = m.update_pattern("PAT-0001", 0.96, 96.0, "CRITICAL", "BLOCK", "TRAFFIC BLOCKED", True)
        self.assertEqual(updated["occurrence_count"], 2)
        self.assertAlmostEqual(updated["average_confidence"], 0.97)
        self.assertEqual(updated["successful_containments"], 2)
        stats = m.get_statistics()
        self.assertEqual((stats["total_events"], stats["total_patterns"], stats["repeated_patterns"]), (1, 1, 1))

    def test_verification_success_and_failure(self):
        m = self.memory
        m.create_pattern("PAT-T", "FP-T", 1, 0.99, 99.0, "CRITICAL", "BLOCK", "TRAFFIC BLOCKED", False)
        m.store_event("EVT-T", 1, 0.99, 99.0, "CRITICAL", (1, 9), "BLOCK", "TRAFFIC BLOCKED", True,
                      "FP-T", pattern_id="PAT-T")
        self.assertEqual(m.get_event("EVT-T")["containment_verified"], 0)
        m.record_containment_verification("EVT-T", "PAT-T", True)
        self.assertEqual(m.get_event("EVT-T")["containment_verified"], 1)
        m.record_verification_result("PAT-T", False)
        p = m.get_pattern("PAT-T")
        self.assertEqual((p["successful_containments"], p["failed_containments"]), (1, 1))
        s = m.get_statistics()
        self.assertEqual((s["successful_containments"], s["failed_containments"], s["verified_events"]), (1, 1, 1))

    def test_recovery_audit(self):
        self.memory.store_recovery_audit("EVT-R", "RUN", 7, 0, 1, "ALLOW", "FAILED", "ESCALATE",
                                         "BLOCK", "SIMULATED_SUCCESS", True, {"oracle_assisted": True})
        row = self.memory.get_recovery_audit("EVT-R")
        self.assertEqual((row["evaluation_mode"], row["recovery_verified"]), ("OFFLINE_ORACLE_ASSISTED", 1))

    def test_endpoint_and_apt_tables_are_lazy(self):
        tables = {r[0] for r in self.memory.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("endpoint_healing_audit", tables)
        self.assertNotIn("apt_campaigns", tables)

    def test_ioc_memory_reports_previous_hosts(self):
        m = self.memory
        m.create_campaign("C1", "RUN", None)
        self.assertEqual(m.record_ioc("C1", "abc", "HOST-A"), [])
        self.assertEqual(m.record_ioc("C1", "abc", "HOST-B"), ["HOST-A"])
        m.store_campaign_event("C1", 1, "TA0001", "Initial Access", "HOST-A", "x", "abc", "d")
        m.store_campaign_event("C1", 2, "TA0008", "Lateral Movement", "HOST-B", "x", "abc", "d")
        rec = m.get_campaign("C1")
        self.assertEqual((rec["campaign"]["hosts"], rec["campaign"]["stage_count"]), ("HOST-A,HOST-B", 2))


# ======================================================================
# RL AGENT, REWARD, THREAT ASSESSMENT
# ======================================================================

class RLAgentTests(unittest.TestCase):

    def test_state_buckets(self):
        a = RLAgent()
        self.assertEqual(a.get_state(0, 1.0), (0, 9))
        self.assertEqual(a.get_state(1, 0.55), (1, 5))
        self.assertEqual(a.get_state(1, 1.7), (1, 9))   # clamped
        self.assertEqual(a.get_state(0, -0.2), (0, 0))  # clamped

    def test_reward_table_matches_documentation(self):
        table = {(1, "BLOCK"): 10, (1, "ALERT"): 2, (1, "ALLOW"): -15,
                 (0, "ALLOW"): 5, (0, "ALERT"): -2, (0, "BLOCK"): -10}
        for (label, action), reward in table.items():
            self.assertEqual(get_reward(label, action), reward)
        self.assertEqual(get_reward(1, "ISOLATE"), -10)  # unmatched fallback

    def test_terminal_update(self):
        a = RLAgent(alpha=0.1)
        a.update_q((1, 9), "BLOCK", 10, None, done=True)
        self.assertAlmostEqual(a.q_table[(1, 9)]["BLOCK"], 1.0)

    def test_evaluation_is_deterministic_and_frozen(self):
        import joblib
        q = joblib.load(cfg.Q_TABLE_FILE)
        a = RLAgent()
        a.q_table = {k: dict(v) for k, v in q.items()}
        a.set_evaluation_mode()
        picks = {a.choose_action(s, training=False) for s in [(1, 9)] * 50}
        self.assertEqual(len(picks), 1)
        self.assertEqual(a.q_table, q)  # choosing actions never changes known states

    def test_threat_assessment_thresholds(self):
        t = ThreatAssessment()
        self.assertEqual(t.assess(1, 0.99)["severity"], "CRITICAL")
        self.assertEqual(t.assess(1, 0.60)["severity"], "HIGH")
        self.assertEqual(t.assess(0, 0.70)["severity"], "MEDIUM")
        self.assertEqual(t.assess(0, 1.00)["severity"], "LOW")


# ======================================================================
# HELD-OUT SPLIT + PATH GUARD
# ======================================================================

class SplitAndGuardTests(unittest.TestCase):

    def test_heldout_split_has_zero_rl_overlap(self):
        import evaluate_self_healing_heldout as h
        df = pd.DataFrame({"Label": ["Benign"] * 9000 + ["DDoS"] * 1000})
        train_idx, heldout = h.build_heldout_split(df)
        self.assertEqual(len(train_idx), 2000)
        self.assertEqual(len(heldout), 2000)
        self.assertEqual(len(set(train_idx) & set(heldout.index)), 0)
        # Same seeds -> same rows every time (reproducible)
        self.assertTrue(h.build_heldout_split(df)[1].index.equals(heldout.index))

    def test_assert_inside_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertTrue(str(cfg.assert_inside(root / "a" / "b.txt", root)).endswith("b.txt"))
            with self.assertRaises(PermissionError):
                cfg.assert_inside(root / ".." / "escape.txt", root)

    def test_create_run_dir_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = cfg.RUNS_DIR
            cfg.RUNS_DIR = Path(tmp)
            try:
                cfg.create_run_dir("X")
                with self.assertRaises(FileExistsError):
                    cfg.create_run_dir("X")
            finally:
                cfg.RUNS_DIR = original


if __name__ == "__main__":
    unittest.main()
