"""Tests for the controlled multi-stage APT campaign simulation (temp folders only)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apt_simulation import IMPLANT_PATH, STAGES, run_apt_campaign  # noqa: E402
from response_verifier import ResponseVerifier  # noqa: E402
from self_healing_engine import SelfHealingEngine  # noqa: E402
from threat_memory import ThreatMemory  # noqa: E402


class APTCampaignTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.memory = ThreatMemory(str(Path(cls.tmp.name) / "m.db"))
        cls.result = run_apt_campaign(
            cls.tmp.name, "TEST", ResponseVerifier(), SelfHealingEngine(), cls.memory,
            trigger_incident={"event_id": "EVT-TEST-0001"},
        )

    @classmethod
    def tearDownClass(cls):
        cls.memory.close()
        cls.tmp.cleanup()

    def test_attack_sequence_is_ordered_and_spans_two_hosts(self):
        t = self.result["timeline"]
        self.assertEqual([s["seq"] for s in t], list(range(1, len(STAGES) + 1)))
        self.assertEqual([s["tactic_id"] for s in t], ["TA0001", "TA0003", "TA0006", "TA0008", "TA0003", "TA0040"])
        self.assertEqual({s["host_id"] for s in t}, {"HOST-A", "HOST-B"})

    def test_lateral_movement_correlated_by_identical_hash(self):
        c = self.result["correlations"]
        self.assertEqual(len(c), 1)
        self.assertEqual((c[0]["from_hosts"], c[0]["to_host"], c[0]["artifact"]),
                         (["HOST-A"], "HOST-B", IMPLANT_PATH))
        hashes = {s["sha256"] for s in self.result["timeline"] if s["artifact"] == IMPLANT_PATH}
        self.assertEqual(len(hashes), 1)

    def test_memory_links_all_stages(self):
        rec = self.result["memory_record"]
        self.assertEqual(len(rec["events"]), 6)
        self.assertEqual(rec["campaign"]["trigger_event_id"], "EVT-TEST-0001")
        self.assertEqual(rec["campaign"]["verdict"], "CAMPAIGN_CONTAINED_VERIFIED")

    def test_known_ioc_flagged_on_second_host(self):
        q_b = self.result["responses"]["HOST-B"]["quarantine_actions"]
        self.assertTrue(any(q["known_campaign_ioc"] for q in q_b))
        q_a = self.result["responses"]["HOST-A"]["quarantine_actions"]
        self.assertFalse(any(q["known_campaign_ioc"] for q in q_a))

    def test_both_hosts_verified_and_rescan_clean(self):
        for host, r in self.result["responses"].items():
            self.assertEqual(r["recovery_status"], "HEALED_VERIFIED", host)
            self.assertEqual(r["decision"]["healing_action"], "ENDPOINT_RESTORED")
        for host, s in self.result["rescan"].items():
            self.assertEqual((s["ioc_files_remaining"], s["rogue_persistence_remaining"]), ([], []))
            self.assertTrue(s["matches_clean_baseline"], host)
        self.assertEqual(self.result["verdict"], "CAMPAIGN_CONTAINED_VERIFIED")

    def test_report_written_inside_sandbox(self):
        report = Path(self.tmp.name) / "apt_sim" / "campaign_report.json"
        self.assertTrue(report.exists())
        self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["verdict"], self.result["verdict"])


class APTFailureTests(unittest.TestCase):

    def test_verdict_fails_if_a_host_cannot_be_restored(self):
        import apt_simulation as apt

        original = apt._stage_impact

        def impact_and_poison(hosts):
            host, rel, desc = original(hosts)
            # attacker also corrupts the backup copy on HOST-B
            hosts["HOST-B"].write_text(hosts["HOST-B"].baseline_store / "files/payroll_report.txt", "ENCRYPTED::backup\n")
            return host, rel, desc + " + backup corrupted"

        stages = list(apt.STAGES)
        stages[-1] = (stages[-1][0], stages[-1][1], impact_and_poison)

        with tempfile.TemporaryDirectory() as tmp:
            memory = ThreatMemory(str(Path(tmp) / "m.db"))
            saved = apt.STAGES
            apt.STAGES = stages
            try:
                r = apt.run_apt_campaign(tmp, "FAIL", ResponseVerifier(), SelfHealingEngine(), memory)
            finally:
                apt.STAGES = saved
                memory.close()

        self.assertEqual(r["responses"]["HOST-A"]["recovery_status"], "HEALED_VERIFIED")
        self.assertEqual(r["responses"]["HOST-B"]["recovery_status"], "HEALING_INCOMPLETE")
        self.assertEqual(r["responses"]["HOST-B"]["decision"]["healing_action"], "SOC_REVIEW")
        self.assertEqual(r["verdict"], "CAMPAIGN_NOT_CONTAINED")


if __name__ == "__main__":
    unittest.main()
