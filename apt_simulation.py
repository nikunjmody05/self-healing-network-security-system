"""
Controlled multi-stage APT campaign simulation across two simulated hosts.

What this demonstrates
----------------------
A scripted, auditable attack sequence labelled with MITRE ATT&CK tactic IDs:

    HOST-A (workstation)  TA0001 Initial Access   -> implant dropped
                          TA0003 Persistence      -> startup entry added
                          TA0006 Credential Access-> dummy credential dump
    HOST-B (file server)  TA0008 Lateral Movement -> SAME implant copied
                                                     (simulated, folder copy)
                          TA0003 Persistence      -> startup entry added
                          TA0040 Impact           -> file encrypted, config tampered

Every stage is written to threat memory (apt_campaign_events). The implant's
SHA-256 is recorded as an IOC; when it appears on HOST-B the memory reports
that it was already seen on HOST-A, which is the cross-host correlation.

Response: the existing EndpointHealer heals HOST-A (patient zero) then
HOST-B, each verified by the ResponseVerifier in ENDPOINT_INTEGRITY mode.
The campaign verdict requires every host to verify AND a final re-scan of
both hosts to find no campaign IOC anywhere.

SCOPE: everything happens inside runs/<RUN_ID>/apt_sim/. "Lateral movement"
is a file copy between two sandbox folders. No real network traffic, no real
hosts, no registry, no firewall. This is not a claim of detecting real
lateral movement.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path

from endpoint_healing import (
    PERSISTENCE_FILE,
    EndpointHealer,
    SimulatedEndpoint,
    sha256_file,
)


IMPLANT_PATH = "files/temp/svc_update_helper.ps1.txt"
IMPLANT_BYTES = (
    "SIMULATED APT IMPLANT - INERT TEXT FOR THE PROJECT DEMO\n"
    "campaign=simulated; beacon_interval=300; c2=203.0.113.50\n"
).encode("utf-8")

HOSTS = {
    "HOST-A": "Workstation (patient zero)",
    "HOST-B": "File server (lateral movement target)",
}


def _now():
    return datetime.now().isoformat(timespec="seconds")


def campaign_id_for(run_id):
    digest = hashlib.sha256(IMPLANT_BYTES).hexdigest()[:10].upper()
    return f"APT-{digest}-{run_id}"


# ============================================================
# ATTACK STAGES (inert, sandbox only)
# ============================================================

def _add_persistence(endpoint, name, command):
    entries = endpoint.read_persistence()
    entries.append({"name": name, "command": command})
    endpoint.write_json(endpoint.live / PERSISTENCE_FILE, entries)
    return PERSISTENCE_FILE


def _stage_initial_access(hosts):
    a = hosts["HOST-A"]
    path = a.live / IMPLANT_PATH
    a.safe(path).parent.mkdir(parents=True, exist_ok=True)
    a.safe(path).write_bytes(IMPLANT_BYTES)
    return "HOST-A", IMPLANT_PATH, "Phishing payload drops the implant"


def _stage_persistence_a(hosts):
    rel = _add_persistence(hosts["HOST-A"], "OfficeUpdater",
                           "powershell -w hidden " + IMPLANT_PATH)
    return "HOST-A", rel, "Startup entry 'OfficeUpdater' added"


def _stage_credential_access(hosts):
    a = hosts["HOST-A"]
    rel = "files/temp/lsass_dump_simulated.txt"
    a.write_text(a.live / rel, "SIMULATED CREDENTIAL DUMP - DUMMY DATA ONLY\nuser=svc_backup hash=0000\n")
    return "HOST-A", rel, "Dummy credential dump written"


def _stage_lateral_movement(hosts):
    b = hosts["HOST-B"]
    path = b.live / IMPLANT_PATH
    b.safe(path).parent.mkdir(parents=True, exist_ok=True)
    # Same bytes as on HOST-A -> identical IOC hash
    b.safe(path).write_bytes((hosts["HOST-A"].live / IMPLANT_PATH).read_bytes())
    return "HOST-B", IMPLANT_PATH, "Implant copied to file server (simulated lateral movement)"


def _stage_persistence_b(hosts):
    rel = _add_persistence(hosts["HOST-B"], "WinUpdateHelper",
                           "powershell -w hidden " + IMPLANT_PATH)
    return "HOST-B", rel, "Startup entry 'WinUpdateHelper' added"


def _stage_impact(hosts):
    b = hosts["HOST-B"]
    payroll = b.live / "files/payroll_report.txt"
    b.write_text(payroll, "ENCRYPTED::" + payroll.read_text(encoding="utf-8").encode("utf-8").hex() + "\n")
    config_path = b.live / "config/app_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["firewall_profile"] = "disabled"
    config["remote_admin_enabled"] = True
    b.write_json(config_path, config)
    return "HOST-B", "files/payroll_report.txt", "File encrypted and firewall profile disabled in config"


STAGES = [
    ("TA0001", "Initial Access", _stage_initial_access),
    ("TA0003", "Persistence", _stage_persistence_a),
    ("TA0006", "Credential Access", _stage_credential_access),
    ("TA0008", "Lateral Movement (simulated)", _stage_lateral_movement),
    ("TA0003", "Persistence", _stage_persistence_b),
    ("TA0040", "Impact", _stage_impact),
]


# ============================================================
# CAMPAIGN
# ============================================================

def run_apt_campaign(run_dir, run_id, verifier, engine, memory,
                     trigger_incident=None):
    """Execute the simulated campaign, correlate it, heal and verify."""

    base = Path(run_dir) / "apt_sim"
    campaign_id = campaign_id_for(run_id)

    hosts = {}
    for host_id in HOSTS:
        ep = SimulatedEndpoint(base / host_id, host_id)
        ep.provision()
        ep.snapshot_baseline()
        hosts[host_id] = ep

    clean = {h: ep.capture_state() for h, ep in hosts.items()}

    memory.create_campaign(
        campaign_id, run_id,
        (trigger_incident or {}).get("event_id"),
    )

    # ---------------- attack sequence ----------------
    timeline = []
    for seq, (tactic_id, tactic, stage) in enumerate(STAGES, start=1):
        host_id, artifact, description = stage(hosts)
        artifact_path = hosts[host_id].live / artifact
        digest = sha256_file(artifact_path) if artifact_path.exists() else None
        memory.store_campaign_event(campaign_id, seq, tactic_id, tactic,
                                    host_id, artifact, digest, description)
        timeline.append({
            "seq": seq, "time": _now(), "tactic_id": tactic_id,
            "tactic": tactic, "host_id": host_id, "artifact": artifact,
            "sha256": digest, "description": description,
        })

    # ---------------- detection + correlation ----------------
    detection = {}
    correlations = []

    for host_id in HOSTS:           # patient zero first
        ep = hosts[host_id]
        healer = EndpointHealer(ep)
        manifest, _trusted, _problems = healer.check_baseline_trust()
        state = ep.capture_state()
        found = healer.detect(manifest, state)

        iocs = []
        for rel in found["unauthorized_files"]:
            digest = state["files"][rel]
            seen_before = memory.record_ioc(campaign_id, digest, host_id)
            iocs.append({"path": rel, "sha256": digest,
                         "previously_seen_on": seen_before,
                         "known_ioc": bool(seen_before)})
            if seen_before:
                correlations.append({
                    "type": "SHARED_IOC_HASH",
                    "sha256": digest,
                    "artifact": rel,
                    "from_hosts": seen_before,
                    "to_host": host_id,
                    "interpretation": (
                        "Identical implant on a second host: linked to the "
                        "same campaign (simulated lateral movement)."
                    ),
                })

        detection[host_id] = {"findings": found, "iocs": iocs}

    # ---------------- response: heal each host ----------------
    responses = {}
    for host_id in HOSTS:
        report = EndpointHealer(hosts[host_id]).heal(f"{campaign_id}-{host_id}")
        known = {i["sha256"] for i in detection[host_id]["iocs"] if i["known_ioc"]}
        for q in report["quarantine_actions"]:
            q["known_campaign_ioc"] = q["sha256"] in known

        verification = verifier.verify(
            action="ENDPOINT_RESTORE", response=report["recovery_status"],
            prediction=1, severity="CRITICAL",
            verification_mode="ENDPOINT_INTEGRITY", observed_outcome=report,
        )
        decision = engine.assess_endpoint_healing(verification)

        responses[host_id] = {
            "recovery_status": report["recovery_status"],
            "verified": report["verified"],
            "integrity_summary": report["integrity_summary"],
            "quarantine_actions": report["quarantine_actions"],
            "persistence_removed": report["persistence_removed"],
            "restoration_actions": report["restoration_actions"],
            "failure_reasons": report["failure_reasons"],
            "verification": verification,
            "decision": decision,
            "report_path": f"apt_sim/{host_id}/{report['report_path']}",
        }

    # ---------------- campaign-wide re-scan ----------------
    ioc_hashes = {i["sha256"] for d in detection.values() for i in d["iocs"]}
    rescan = {}
    for host_id, ep in hosts.items():
        state = ep.capture_state()
        remaining = sorted(rel for rel, h in state["files"].items() if h in ioc_hashes)
        rogue = [e.get("name") for e in state["persistence_entries"]
                 if e.get("name") not in {x.get("name") for x in clean[host_id]["persistence_entries"]}]
        rescan[host_id] = {
            "ioc_files_remaining": remaining,
            "rogue_persistence_remaining": rogue,
            "matches_clean_baseline": state["files"] == clean[host_id]["files"],
        }

    contained = (
        all(r["verified"] for r in responses.values())
        and all(not r["ioc_files_remaining"] and not r["rogue_persistence_remaining"]
                and r["matches_clean_baseline"] for r in rescan.values())
    )
    verdict = "CAMPAIGN_CONTAINED_VERIFIED" if contained else "CAMPAIGN_NOT_CONTAINED"
    memory.set_campaign_verdict(campaign_id, verdict)

    result = {
        "campaign_id": campaign_id,
        "mode": "CONTROLLED_APT_SIMULATION",
        "hosts": HOSTS,
        "trigger_incident": trigger_incident,
        "timeline": timeline,
        "detection": detection,
        "correlations": correlations,
        "responses": responses,
        "rescan": rescan,
        "verdict": verdict,
        "memory_record": memory.get_campaign(campaign_id),
        "scope_note": (
            "Simulated campaign inside an isolated project folder. Lateral "
            "movement is a file copy between two sandbox hosts. No real "
            "network traffic, hosts, registry or firewall are involved."
        ),
    }

    out = base / "campaign_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    result["report_path"] = "apt_sim/campaign_report.json"

    return result


if __name__ == "__main__":

    import tempfile

    from response_verifier import ResponseVerifier
    from self_healing_engine import SelfHealingEngine
    from threat_memory import ThreatMemory

    with tempfile.TemporaryDirectory() as tmp:
        mem = ThreatMemory(str(Path(tmp) / "m.db"))
        r = run_apt_campaign(tmp, "DEMO", ResponseVerifier(), SelfHealingEngine(), mem)
        mem.close()
        for t in r["timeline"]:
            print(t["seq"], t["tactic_id"], t["tactic"], t["host_id"], t["artifact"])
        print("correlations:", [(c["from_hosts"], c["to_host"]) for c in r["correlations"]])
        for h, resp in r["responses"].items():
            print(h, resp["recovery_status"], resp["integrity_summary"], resp["decision"]["healing_action"])
        print("rescan:", r["rescan"])
        print("VERDICT:", r["verdict"])
