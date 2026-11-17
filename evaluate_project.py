"""
Project evaluation report (no training, no pipeline execution).

    python evaluate_project.py [--standard runs/<ID>] [--heldout runs/<ID>-heldout]

Reads the saved outputs of an existing standard Phase 4 run and an existing
held-out Phase 4C.5 run (latest ones by default), plus the dataset's Label
column for the overlap analysis, and writes:

    runs/<RUN_ID>-evaluation/evaluation_report.md
    runs/<RUN_ID>-evaluation/evaluation_results.json
    runs/<RUN_ID>-evaluation/*.png

Every result is tagged with its category:

    HISTORICAL  values recorded by earlier scripts, not regenerated here
    IN-SAMPLE   standard Phase 4 sample (also RL training rows; inside the
                Random Forest's 100k training sample)
    HELD-OUT    Phase 4C.5 sample (0 RL-training overlap)
    SIMULATED   controlled endpoint / APT simulation inside the sandbox
"""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

import project_config as cfg
from rl_agent import get_reward


ACTIONS = ["ALLOW", "ALERT", "BLOCK"]


# ============================================================
# LOADING
# ============================================================

def latest_run(kind):
    """Latest run folder of a given evaluation set."""

    candidates = []

    for folder in sorted(cfg.RUNS_DIR.glob("*")):

        if kind == "STANDARD_PHASE4":
            path = folder / "pipeline_summary.json"
        else:
            path = folder / "heldout_self_healing_summary.json"

        if path.exists():
            summary = json.loads(path.read_text(encoding="utf-8"))
            if summary.get("evaluation_set") == kind:
                candidates.append(folder)

    if not candidates:
        raise SystemExit(f"No {kind} run found in {cfg.RUNS_DIR}")

    return candidates[-1]


def load_standard(folder):

    df = pd.read_csv(folder / "security_events.csv")

    return pd.DataFrame({
        "true_label": df["true_label"],
        "prediction": df["prediction"],
        "state": df["state"],
        "unseen": df["unseen_rl_state"].astype(bool),
        "action": df["action"],
        "verification": df["initial_verification_status"],
        "recovery_required": df["initial_recovery_required"].astype(bool),
        "healing_action": df["healing_action"],
        "recovery_action": df["recovery_action"],
        "recovery_status": df["recovery_status"],
        "final_containment": df["post_recovery_simulated_containment"].astype(bool),
        "pattern_status": df["pattern_status"],
        "reward": df["reward"],
    })


def load_heldout(folder):

    df = pd.read_csv(folder / "heldout_self_healing_events.csv")

    return pd.DataFrame({
        "true_label": df["true_label"],
        "prediction": df["prediction"],
        "state": df["rl_state"],
        "unseen": df["unseen_rl_state"].astype(bool),
        "action": df["initial_action"],
        "verification": df["initial_verification"],
        "recovery_required": df["recovery_required"].astype(bool),
        "healing_action": df["healing_action"],
        "recovery_action": df["recovery_action"],
        "recovery_status": df["recovery_status"],
        "final_containment": df["post_recovery_simulated_containment"].astype(bool),
        "pattern_status": df["pattern_status"],
        "reward": df["reward"],
    })


# ============================================================
# ANALYSES
# ============================================================

def pct(a, b):
    return round(100.0 * a / b, 2) if b else 0.0


def rf_metrics(ev):

    tp = int(((ev.true_label == 1) & (ev.prediction == 1)).sum())
    tn = int(((ev.true_label == 0) & (ev.prediction == 0)).sum())
    fp = int(((ev.true_label == 0) & (ev.prediction == 1)).sum())
    fn = int(((ev.true_label == 1) & (ev.prediction == 0)).sum())
    p, r = pct(tp, tp + fp), pct(tp, tp + fn)

    return {
        "flows": len(ev), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": pct(tp + tn, len(ev)), "precision": p, "recall": r,
        "f1": round(2 * p * r / (p + r), 2) if p + r else 0.0,
    }


def policy_outcome(ev, actions):

    attack = ev.true_label == 1
    benign = ~attack
    rewards = [get_reward(int(t), a) for t, a in zip(ev.true_label, actions)]
    actions = pd.Series(list(actions), index=ev.index)

    return {
        "total_reward": int(sum(rewards)),
        "allow": int((actions == "ALLOW").sum()),
        "alert": int((actions == "ALERT").sum()),
        "block": int((actions == "BLOCK").sum()),
        "attacks_blocked": int((attack & (actions == "BLOCK")).sum()),
        "attacks_alert_only": int((attack & (actions == "ALERT")).sum()),
        "attacks_allowed": int((attack & (actions == "ALLOW")).sum()),
        "false_blocks": int((benign & (actions == "BLOCK")).sum()),
        "unnecessary_alerts": int((benign & (actions == "ALERT")).sum()),
        "initial_containment_pct": pct(int((attack & (actions == "BLOCK")).sum()), int(attack.sum())),
    }


def rl_vs_baseline(ev):

    baseline = ["BLOCK" if p == 1 else "ALLOW" for p in ev.prediction]
    oracle = ["BLOCK" if t == 1 else "ALLOW" for t in ev.true_label]

    rl = policy_outcome(ev, ev.action)
    base = policy_outcome(ev, baseline)
    best = policy_outcome(ev, oracle)

    # The recorded reward must equal the recomputed RL reward
    assert rl["total_reward"] == int(ev.reward.sum()), "reward mismatch"

    disagreements = ev[[a != b for a, b in zip(ev.action, baseline)]]

    return {
        "q_learning_frozen": rl,
        "fixed_baseline_rf_prediction": base,
        "oracle_upper_bound": best,
        "reward_difference_rl_minus_baseline": rl["total_reward"] - base["total_reward"],
        "flows_where_policies_differ": int(len(disagreements)),
        "differences_by_state": {
            str(k): int(v) for k, v in Counter(disagreements.state).items()
        },
    }


def unseen_states(ev, q_table):

    all_states = [f"({p}, {b})" for p in (0, 1) for b in range(10)]
    in_table = sorted(str(s) for s in q_table)
    visited = Counter(ev.state)

    return {
        "q_table_states": in_table,
        "possible_states": len(all_states),
        "states_missing_from_q_table": [s for s in all_states if s not in in_table],
        "unseen_state_flows": int(ev.unseen.sum()),
        "unseen_states_visited": {
            s: int(c) for s, c in visited.items() if s not in in_table
        },
        "unseen_state_outcomes": dict(Counter(
            f"{'ATTACK' if t else 'BENIGN'}->{a}"
            for t, a in zip(ev[ev.unseen].true_label, ev[ev.unseen].action)
        )),
        "fallback_action": "ALERT",
    }


def failure_paths(ev):

    attack = ev.true_label == 1

    return {
        "rf_false_negatives": int((attack & (ev.prediction == 0)).sum()),
        "rf_false_positives": int(((~attack) & (ev.prediction == 1)).sum()),
        "attack_allowed_initially": int((attack & (ev.action == "ALLOW")).sum()),
        "attack_alert_only_initially": int((attack & (ev.action == "ALERT")).sum()),
        "benign_blocked": int(((~attack) & (ev.action == "BLOCK")).sum()),
        "benign_alerted": int(((~attack) & (ev.action == "ALERT")).sum()),
        "recovery_required": int((attack & ev.recovery_required).sum()),
        "recovery_status_counts": dict(Counter(ev[attack & ev.recovery_required].recovery_status)),
        "recovery_actions_taken": dict(Counter(ev[attack & ev.recovery_required].recovery_action.fillna("NONE"))),
        "attacks_uncontained_after_recovery": int((attack & ~ev.final_containment).sum()),
        "false_block_rollback": (
            "NOT IMPLEMENTED: a benign flow that is blocked is recorded as "
            "FALSE_BLOCK but no rollback action exists (future work)."
        ),
        "block_failure_isolate_path": (
            "Code path exists (SelfHealingEngine recommends ISOLATE when a "
            "BLOCK fails) but ISOLATE is not executable by the ResponseEngine; "
            "the simulated BLOCK never fails, so this path was not exercised "
            "in this data. Covered by unit tests only."
        ),
    }


def pattern_reuse(ev):
    """
    Counterfactual 'no pattern reuse' comparison.

    REUSE_DEFENSE is chosen only when the initial response was verified
    successful and no recovery is needed, and it recommends the SAME action.
    Disabling reuse would therefore relabel those events as MAINTAIN without
    changing any action, containment or reward. This function checks that
    property on the actual events instead of assuming it.
    """

    reuse = ev[ev.healing_action == "REUSE_DEFENSE"]

    only_verified = bool((reuse.verification == "SUCCESS").all())
    no_recovery = bool((~reuse.recovery_required).all())

    return {
        "reuse_decisions": int(len(reuse)),
        "reuse_share_of_rf_detected_threats": pct(len(reuse), int((ev.prediction == 1).sum())),
        "pattern_status_counts": dict(Counter(ev.pattern_status)),
        "all_reuse_events_were_verified_success": only_verified,
        "no_reuse_event_required_recovery": no_recovery,
        "with_reuse": {
            "total_reward": int(ev.reward.sum()),
            "final_contained_attacks": int(((ev.true_label == 1) & ev.final_containment).sum()),
        },
        "without_reuse_counterfactual": {
            "total_reward": int(ev.reward.sum()),
            "final_contained_attacks": int(((ev.true_label == 1) & ev.final_containment).sum()),
            "relabelled_reuse_to_maintain": int(len(reuse)),
        },
        "finding": (
            "Pattern reuse does not change actions, containment or reward in "
            "this offline evaluation, because it only fires after a verified "
            "success and recommends the same action. Its value is the audit "
            "trail and historical context, not a measured containment gain."
            if only_verified and no_recovery else
            "Some reuse events did not follow a verified success; the "
            "counterfactual above is not exact."
        ),
    }


def overlap_analysis():
    """Index-level overlap between RF, RL, standard and held-out samples."""

    df = pd.read_parquet(cfg.DATA_PATH, columns=["Label"])

    rf_sample = df.sample(100000, random_state=42).index
    standard = df.sample(n=2000, random_state=42).index
    heldout = df.drop(index=standard).sample(n=2000, random_state=84).index

    return {
        "dataset_rows": int(len(df)),
        "rf_sample_rows": 100000,
        "rf_split": "train_test_split(test_size=0.2) WITHOUT random_state -> exact RF train rows unknown",
        "standard_rows_in_rf_100k_sample": int(len(standard.intersection(rf_sample))),
        "standard_sample_is_prefix_of_rf_sample": bool((rf_sample[:2000] == standard).all()),
        "standard_rows_expected_in_rf_train_split": "about 80% (~1,600), exact count unknown",
        "rl_training_rows_equal_standard_rows": True,
        "heldout_rows_in_rl_training": int(len(heldout.intersection(standard))),
        "heldout_rows_in_rf_100k_sample": int(len(heldout.intersection(rf_sample))),
        "heldout_rows_expected_in_rf_train_split": "about 80% of those (~22 of 2,000)",
    }


def historical():

    root = cfg.BASE_DIR
    out = {
        "source_note": "Recorded by earlier scripts; NOT regenerated by this report.",
        "rf_cic_test_accuracy": "98.47% (detection_model.py, 20,000-row test split of the 100k sample; split seed not fixed)",
        "rf_cic_confusion_matrix": "TN 15,562 · FP 47 · FN 258 · TP 4,133",
        "rf_unsw_nb15_accuracy": "90.43% (unsw.py, official UNSW-NB15 train/test sets)",
        "standalone_rl_simulation": "25,324 reward over 5,000 steps (simulation.py, earlier agent version)",
    }

    path = root / "rl_training_summary.csv"
    if path.exists():
        out["rl_training_summary_train_rl_py"] = next(csv.DictReader(open(path, encoding="utf-8")))

    return out


def simulated(standard_dir):

    out = {}
    db = standard_dir / "threat_memory_run.db"

    reports = sorted(standard_dir.glob("endpoint_sim/HOST-*/reports/healing_report_*.json"))
    out["endpoint_healing"] = [
        {
            "host": r["host_id"], "scenario": r.get("scenario"),
            "status": r["recovery_status"],
            "sha256_passed": f"{r['integrity_summary']['files_passed']}/{r['integrity_summary']['files_checked']}",
            "decision": (r.get("final_healing_decision") or {}).get("healing_action"),
        }
        for r in (json.loads(p.read_text(encoding="utf-8")) for p in reports)
    ]

    apt = standard_dir / "apt_sim" / "campaign_report.json"
    if apt.exists():
        a = json.loads(apt.read_text(encoding="utf-8"))
        out["apt_campaign"] = {
            "campaign_id": a["campaign_id"],
            "stages": len(a["timeline"]),
            "hosts": list(a["hosts"]),
            "cross_host_links": len(a["correlations"]),
            "host_status": {h: r["recovery_status"] for h, r in a["responses"].items()},
            "verdict": a["verdict"],
        }
    else:
        out["apt_campaign"] = "not present in this run"

    out["database"] = db.name if db.exists() else "missing"
    return out


# ============================================================
# CHARTS
# ============================================================

def chart_rl_vs_baseline(results, out):

    labels = ["Initial containment %", "Attacks allowed", "False blocks", "Unnecessary alerts"]
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))

    for ax, (name, block) in zip(axes, results.items()):
        rl, base = block["q_learning_frozen"], block["fixed_baseline_rf_prediction"]
        keys = ["initial_containment_pct", "attacks_allowed", "false_blocks", "unnecessary_alerts"]
        x = range(len(keys))
        ax.bar([i - 0.2 for i in x], [rl[k] for k in keys], 0.4, label=f"Q-learning ({rl['total_reward']:,})")
        ax.bar([i + 0.2 for i in x], [base[k] for k in keys], 0.4, label=f"Fixed baseline ({base['total_reward']:,})")
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, rotation=12, fontsize=8)
        ax.set_title(name)
        ax.legend(title="policy (total reward)", fontsize=8)
        ax.grid(axis="y", alpha=0.3)

    fig.suptitle("Frozen Q-learning vs fixed baseline (RF prediction -> BLOCK/ALLOW)")
    fig.tight_layout()
    fig.savefig(out / "rl_vs_baseline.png", dpi=200)
    plt.close(fig)


def chart_containment(std_fail, ho_fail, std_rl, ho_rl, out):

    fig, ax = plt.subplots(figsize=(8, 4.5))
    names = ["IN-SAMPLE standard", "HELD-OUT 4C.5"]
    initial = [std_rl["initial_containment_pct"], ho_rl["initial_containment_pct"]]
    attacks = [std_rl["attacks_blocked"] + std_rl["attacks_alert_only"] + std_rl["attacks_allowed"],
               ho_rl["attacks_blocked"] + ho_rl["attacks_alert_only"] + ho_rl["attacks_allowed"]]
    final = [pct(a - f["attacks_uncontained_after_recovery"], a) for a, f in zip(attacks, [std_fail, ho_fail])]
    x = range(2)
    ax.bar([i - 0.2 for i in x], initial, 0.4, label="Initial (frozen RL action)")
    ax.bar([i + 0.2 for i in x], final, 0.4, label="After oracle-assisted recovery")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names)
    ax.set_ylim(90, 100.5)
    ax.set_ylabel("Simulated attack containment (%)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.set_title("Initial vs post-recovery simulated containment")
    fig.tight_layout()
    fig.savefig(out / "containment_initial_vs_recovery.png", dpi=200)
    plt.close(fig)


# ============================================================
# REPORT
# ============================================================

def md_table(rows, header):

    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def write_report(res, out):

    std, ho = res["in_sample_standard"], res["heldout_phase4c5"]
    ov = res["overlap"]
    L = []
    A = L.append

    A("# Evaluation Report — Self-Healing Network Security System for APT\n")
    A(f"Generated from saved run outputs. Standard run: `{res['inputs']['standard_run']}` · "
      f"held-out run: `{res['inputs']['heldout_run']}`. No model was trained or re-run.\n")
    A("Result categories: **HISTORICAL** (earlier scripts, not regenerated) · **IN-SAMPLE** "
      "(standard Phase 4 sample) · **HELD-OUT** (Phase 4C.5) · **SIMULATED** (controlled sandbox).\n")

    A("## 1. Training / evaluation overlap disclosure\n")
    A(md_table([
        ["Dataset rows", f"{ov['dataset_rows']:,}"],
        ["RF training sample", "df.sample(100000, random_state=42), then 80/20 split without a seed"],
        ["Standard Phase 4 rows inside the RF 100k sample", f"{ov['standard_rows_in_rf_100k_sample']} / 2000 (prefix of the same shuffle: {ov['standard_sample_is_prefix_of_rf_sample']})"],
        ["Standard Phase 4 rows in RF *training* split", ov["standard_rows_expected_in_rf_train_split"]],
        ["Standard Phase 4 rows = RL training rows", "Yes (same sample, random_state=42)"],
        ["Held-out rows in RL training", ov["heldout_rows_in_rl_training"]],
        ["Held-out rows inside the RF 100k sample", f"{ov['heldout_rows_in_rf_100k_sample']} / 2000 ({ov['heldout_rows_expected_in_rf_train_split']})"],
    ], ["Item", "Value"]))
    A("\n**Consequence:** standard Phase 4 ML and RL figures are in-sample and must not be "
      "presented as generalisation. Held-out Phase 4C.5 is the evaluation of record.\n")

    A("## 2. Results by category\n")
    A("### HISTORICAL (not regenerated)\n")
    h = res["historical"]
    A(md_table([[k.replace('_', ' '), v if not isinstance(v, dict) else ", ".join(f"{a}={b}" for a, b in v.items())]
                for k, v in h.items()], ["Item", "Value"]))
    A("\n### IN-SAMPLE vs HELD-OUT detection (Random Forest)\n")
    A(md_table([
        [k, std["rf"][k], ho["rf"][k]] for k in ["flows", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1"]
    ], ["Metric", "IN-SAMPLE standard", "HELD-OUT 4C.5"]))

    A("\n## 3. Frozen Q-learning vs fixed baseline\n")
    A("Baseline = follow the RF prediction (ATTACK → BLOCK, BENIGN → ALLOW). Oracle = perfect "
      "knowledge of the label (upper bound, not achievable). Rewards use `get_reward()`.\n")
    rows = []
    for name, block in [("IN-SAMPLE standard", std["rl_vs_baseline"]), ("HELD-OUT 4C.5", ho["rl_vs_baseline"])]:
        for pol in ["q_learning_frozen", "fixed_baseline_rf_prediction", "oracle_upper_bound"]:
            r = block[pol]
            rows.append([name, pol.replace("_", " "), f"{r['total_reward']:,}", r["allow"], r["alert"], r["block"],
                         r["attacks_allowed"], r["attacks_alert_only"], r["false_blocks"], r["unnecessary_alerts"],
                         f"{r['initial_containment_pct']}%"])
    A(md_table(rows, ["Set", "Policy", "Reward", "ALLOW", "ALERT", "BLOCK", "Attacks allowed",
                      "Attacks alert-only", "False blocks", "Unnecessary alerts", "Initial containment"]))
    for name, block in [("IN-SAMPLE", std["rl_vs_baseline"]), ("HELD-OUT", ho["rl_vs_baseline"])]:
        A(f"\n- **{name}:** RL − baseline reward = {block['reward_difference_rl_minus_baseline']:+,}; "
          f"policies differ on {block['flows_where_policies_differ']} flows, by state: {block['differences_by_state']}.")
    A("\n**Interpretation:** the learned policy is almost identical to following the RF prediction. "
      "It differs only in low-confidence or unseen states, where it chooses ALERT. On held-out data this "
      "caught one extra attack (alert instead of allow) but cost unnecessary alerts, so its total reward "
      "is slightly lower than the baseline. The RL contribution is therefore a cautious response policy "
      "for uncertain states, not a reward improvement.\n")

    A("## 4. Unseen RL states\n")
    for name, u in [("IN-SAMPLE", std["unseen_states"]), ("HELD-OUT", ho["unseen_states"])]:
        A(f"- **{name}:** {u['unseen_state_flows']} flows hit states missing from the Q-table "
          f"{u['unseen_states_visited']} → fallback {u['fallback_action']}; outcomes {u['unseen_state_outcomes']}.")
    A(f"- Q-table covers {len(std['unseen_states']['q_table_states'])} of "
      f"{std['unseen_states']['possible_states']} possible states: {', '.join(std['unseen_states']['q_table_states'])}.\n")

    A("## 5. Failure paths\n")
    keys = ["rf_false_negatives", "rf_false_positives", "attack_allowed_initially", "attack_alert_only_initially",
            "benign_blocked", "benign_alerted", "recovery_required", "attacks_uncontained_after_recovery"]
    A(md_table([[k.replace("_", " "), std["failure_paths"][k], ho["failure_paths"][k]] for k in keys],
               ["Failure path", "IN-SAMPLE", "HELD-OUT"]))
    A(f"\n- Recovery outcomes (held-out): {ho['failure_paths']['recovery_status_counts']}, actions {ho['failure_paths']['recovery_actions_taken']}.")
    A(f"- False-block rollback: {ho['failure_paths']['false_block_rollback']}")
    A(f"- BLOCK failure → ISOLATE: {ho['failure_paths']['block_failure_isolate_path']}")
    A("- Recovery is **oracle-assisted**: ground truth reveals the failure after the initial action. It "
      "evaluates the recovery logic; it is not live detection of failed containment.\n")

    A("## 6. Pattern reuse vs no reuse\n")
    for name, p in [("IN-SAMPLE", std["pattern_reuse"]), ("HELD-OUT", ho["pattern_reuse"])]:
        A(f"- **{name}:** {p['reuse_decisions']} reuse decisions ({p['reuse_share_of_rf_detected_threats']}% of "
          f"RF-detected threats); all verified successes: {p['all_reuse_events_were_verified_success']}; "
          f"none needed recovery: {p['no_reuse_event_required_recovery']}. Reward with/without reuse: "
          f"{p['with_reuse']['total_reward']:,} / {p['without_reuse_counterfactual']['total_reward']:,}; "
          f"final contained attacks {p['with_reuse']['final_contained_attacks']} / "
          f"{p['without_reuse_counterfactual']['final_contained_attacks']}.")
    A(f"\n**Finding:** {ho['pattern_reuse']['finding']}\n")

    A("## 7. SIMULATED results (controlled sandbox)\n")
    s = res["simulated"]
    A(md_table([[e["host"], e["scenario"], e["status"], e["sha256_passed"], e["decision"]] for e in s["endpoint_healing"]],
               ["Host", "Scenario", "Status", "SHA-256 passed", "Decision"]))
    a = s["apt_campaign"]
    if isinstance(a, dict):
        A(f"\nMulti-stage APT campaign `{a['campaign_id']}`: {a['stages']} stages across {a['hosts']}, "
          f"{a['cross_host_links']} cross-host IOC link(s), host status {a['host_status']} → **{a['verdict']}**.")
    A("\nThese are file-level simulations in an isolated folder. They are not real Windows remediation, "
      "real lateral movement or live network enforcement.\n")

    A("## 8. Containment summary\n")
    A(md_table([
        ["IN-SAMPLE standard", f"{std['rl_vs_baseline']['q_learning_frozen']['initial_containment_pct']}%",
         f"{pct(std['rf']['tp'] + std['rf']['fn'] - std['failure_paths']['attacks_uncontained_after_recovery'], std['rf']['tp'] + std['rf']['fn'])}%"],
        ["HELD-OUT 4C.5", f"{ho['rl_vs_baseline']['q_learning_frozen']['initial_containment_pct']}%",
         f"{pct(ho['rf']['tp'] + ho['rf']['fn'] - ho['failure_paths']['attacks_uncontained_after_recovery'], ho['rf']['tp'] + ho['rf']['fn'])}%"],
    ], ["Set", "Initial simulated containment", "After oracle-assisted recovery"]))
    A("\nCharts: `rl_vs_baseline.png`, `containment_initial_vs_recovery.png`.\n")

    (out / "evaluation_report.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None):

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--standard")
    parser.add_argument("--heldout")
    parser.add_argument("--skip-overlap", action="store_true",
                        help="Skip reading the dataset (overlap section marked not computed).")
    args = parser.parse_args(argv)

    standard_dir = Path(args.standard) if args.standard else latest_run("STANDARD_PHASE4")
    heldout_dir = Path(args.heldout) if args.heldout else latest_run("HELDOUT_PHASE4C5")

    q_table = joblib.load(cfg.Q_TABLE_FILE)
    std_ev, ho_ev = load_standard(standard_dir), load_heldout(heldout_dir)

    res = {
        "inputs": {"standard_run": standard_dir.name, "heldout_run": heldout_dir.name},
        "overlap": overlap_analysis() if not args.skip_overlap else {"note": "not computed"},
        "historical": historical(),
    }

    for key, ev in [("in_sample_standard", std_ev), ("heldout_phase4c5", ho_ev)]:
        res[key] = {
            "rf": rf_metrics(ev),
            "rl_vs_baseline": rl_vs_baseline(ev),
            "unseen_states": unseen_states(ev, q_table),
            "failure_paths": failure_paths(ev),
            "pattern_reuse": pattern_reuse(ev),
        }

    res["simulated"] = simulated(standard_dir)

    out = cfg.create_run_dir(cfg.new_run_id() + "-evaluation")
    (out / "evaluation_results.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")

    chart_rl_vs_baseline({"IN-SAMPLE standard": res["in_sample_standard"]["rl_vs_baseline"],
                          "HELD-OUT 4C.5": res["heldout_phase4c5"]["rl_vs_baseline"]}, out)
    chart_containment(res["in_sample_standard"]["failure_paths"], res["heldout_phase4c5"]["failure_paths"],
                      res["in_sample_standard"]["rl_vs_baseline"]["q_learning_frozen"],
                      res["heldout_phase4c5"]["rl_vs_baseline"]["q_learning_frozen"], out)

    if "dataset_rows" in res["overlap"]:
        write_report(res, out)
    else:
        print("Overlap skipped: report written without section 1 values.")
        res["overlap"] = {k: "not computed" for k in [
            "dataset_rows", "standard_rows_in_rf_100k_sample", "standard_sample_is_prefix_of_rf_sample",
            "standard_rows_expected_in_rf_train_split", "heldout_rows_in_rl_training",
            "heldout_rows_in_rf_100k_sample", "heldout_rows_expected_in_rf_train_split"]}
        res["overlap"]["dataset_rows"] = 0
        write_report(res, out)

    print(f"Evaluation written to {out}")
    return out


if __name__ == "__main__":
    main()
