"""
Phase 4C.5 — Held-Out Self-Healing Evaluation

Purpose:
Evaluate the complete frozen security pipeline on CIC-IDS2017 flows
that were NOT part of the 2,000-flow RL training sample.

IMPORTANT:
- Random Forest model is frozen.
- Q-table is frozen.
- No Q-learning updates occur.
- RL training rows are explicitly excluded.
- Ground truth is used ONLY after the initial response for offline
  oracle-assisted verification/recovery.
- No real firewall/network containment is performed.
"""

import json
import sys
from collections import Counter

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

import project_config as cfg

from rl_agent import RLAgent, get_reward
from threat_assesment import ThreatAssessment
from response_engine import ResponseEngine
from threat_memory import ThreatMemory
from pattern_engine import PatternEngine
from response_verifier import ResponseVerifier
from self_healing_engine import SelfHealingEngine


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = cfg.DATA_PATH

MODEL_FILE = cfg.MODEL_FILE
Q_TABLE_FILE = cfg.Q_TABLE_FILE

# Outputs go to runs/<RUN_ID>-heldout/ with a FRESH database.
# The historical test_phase4_heldout.db and top-level heldout_* files
# are never opened or written.
RUN_DIR = None
THREAT_MEMORY_FILE = None

RL_TRAINING_SAMPLE_SIZE = 2000
RL_TRAINING_RANDOM_STATE = 42

HELDOUT_SAMPLE_SIZE = 2000
HELDOUT_RANDOM_STATE = 84

RUN_ID = cfg.new_run_id()

PATTERN_FEATURES = [
    "Flow Duration",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Packet Length Variance",
]


# ============================================================
# UTILITY
# ============================================================

def percent(numerator, denominator):

    if denominator == 0:
        return 0.0

    return 100.0 * numerator / denominator


def verify(
    verifier,
    action,
    response,
    prediction,
    severity,
    truth
):

    return verifier.verify(
        action=action,
        response=response,
        prediction=prediction,
        severity=severity,
        verification_mode="SIMULATED",
        true_label=truth,
    )


# ============================================================
# HELD-OUT SPLIT (same logic as before, extracted for testing)
# ============================================================

def build_heldout_split(df):
    """
    Reconstruct the RL training rows (df.sample(2000, random_state=42))
    and draw the held-out sample (2000, random_state=84) from the rest.
    Raises if any held-out row overlaps the RL training rows.
    """

    training_indices = df.sample(
        n=RL_TRAINING_SAMPLE_SIZE,
        random_state=RL_TRAINING_RANDOM_STATE
    ).index

    heldout = df.drop(index=training_indices).sample(
        n=HELDOUT_SAMPLE_SIZE,
        random_state=HELDOUT_RANDOM_STATE
    )

    overlap = set(training_indices).intersection(heldout.index)

    if overlap:
        raise RuntimeError(
            f"DATA LEAKAGE DETECTED: {len(overlap)} held-out rows "
            f"overlap with RL training."
        )

    return training_indices, heldout


# ============================================================
# MAIN
# ============================================================

def main():

    global RUN_DIR, THREAT_MEMORY_FILE

    missing = cfg.check_inputs()

    if missing:
        print("ERROR: missing inputs:", missing)
        sys.exit(1)

    RUN_DIR = cfg.create_run_dir(RUN_ID + "-heldout")
    THREAT_MEMORY_FILE = RUN_DIR / "threat_memory_heldout.db"

    print(f"Run folder: {RUN_DIR}")

    print("\nLoading frozen security models...")

    model = joblib.load(
        MODEL_FILE
    )

    agent = RLAgent()

    agent.load_q_table(
        Q_TABLE_FILE
    )

    agent.set_evaluation_mode()

    assessment_engine = ThreatAssessment()
    response_engine = ResponseEngine()
    verifier = ResponseVerifier()
    healer = SelfHealingEngine()


    # ========================================================
    # LOAD DATASET
    # ========================================================

    print("\nLoading CIC-IDS2017...")

    df = pd.read_parquet(
        DATA_PATH
    )

    df["target"] = df["Label"].apply(
        lambda x: 0 if x == "Benign" else 1
    )

    print(
        f"Dataset records: {len(df):,}"
    )


    # ========================================================
    # RECONSTRUCT EXACT RL TRAINING INDICES
    # ========================================================

    print(
        "\nReconstructing RL training sample..."
    )

    training_indices = df.sample(
        n=RL_TRAINING_SAMPLE_SIZE,
        random_state=RL_TRAINING_RANDOM_STATE
    ).index

    training_index_set = set(
        training_indices.tolist()
    )

    print(
        f"RL training rows reconstructed: "
        f"{len(training_index_set)}"
    )


    # ========================================================
    # REMOVE RL TRAINING ROWS
    # ========================================================

    heldout_pool = df.drop(
        index=training_indices
    )

    print(
        f"Held-out candidate pool: "
        f"{len(heldout_pool):,}"
    )


    # ========================================================
    # SELECT HELD-OUT SAMPLE
    # ========================================================

    heldout = heldout_pool.sample(
        n=HELDOUT_SAMPLE_SIZE,
        random_state=HELDOUT_RANDOM_STATE
    )


    # --------------------------------------------------------
    # Preserve original dataset indices for overlap proof
    # --------------------------------------------------------

    heldout_original_indices = (
        heldout.index.tolist()
    )

    overlap = (
        training_index_set
        .intersection(
            heldout_original_indices
        )
    )

    overlap_count = len(
        overlap
    )


    # ========================================================
    # HARD SAFETY CHECK
    # ========================================================

    if overlap_count != 0:

        raise RuntimeError(
            f"DATA LEAKAGE DETECTED: "
            f"{overlap_count} held-out rows "
            f"overlap with RL training."
        )


    print(
        f"Held-out samples selected: "
        f"{len(heldout):,}"
    )

    print(
        f"Training / held-out overlap: "
        f"{overlap_count}"
    )

    print(
        "HELD-OUT INTEGRITY CHECK: PASSED"
    )


    heldout = heldout.reset_index(
        drop=False
    ).rename(
        columns={
            "index": "original_dataset_index"
        }
    )


    X = heldout.drop(
        columns=[
            "Label",
            "ClassLabel",
            "target",
            "original_dataset_index"
        ],
        errors="ignore"
    )

    y = heldout[
        "target"
    ].to_numpy()


    # ========================================================
    # STORAGE
    # ========================================================

    events = []

    cumulative_reward = 0
    reward_curve = []

    actions = Counter()
    severities = Counter()
    patterns = Counter()
    metrics = Counter()


    # ========================================================
    # HEADER
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "PHASE 4C.5: HELD-OUT SELF-HEALING EVALUATION"
    )

    print(
        "=" * 78
    )

    print(
        f"Run ID: {RUN_ID}"
    )

    print(
        f"Held-out samples: {len(X)}"
    )

    print(
        f"Excluded RL training rows: "
        f"{len(training_index_set)}"
    )

    print(
        f"Overlap: {overlap_count}"
    )

    print(
        f"Frozen Q-table states: "
        f"{len(agent.q_table)}"
    )

    print(
        "No Q-learning updates are performed."
    )

    print(
        "Recovery remains OFFLINE ORACLE-ASSISTED."
    )

    print(
        "=" * 78
    )


    # ========================================================
    # FRESH HELD-OUT MEMORY
    # ========================================================

    memory = ThreatMemory(
        THREAT_MEMORY_FILE
    )


    try:

        pattern_engine = PatternEngine(
            memory
        )


        # ====================================================
        # PROCESS HELD-OUT FLOWS
        # ====================================================

        for i in range(
            len(X)
        ):

            sample = X.iloc[
                [i]
            ]

            row = X.iloc[
                i
            ]

            truth = int(
                y[i]
            )

            original_index = int(
                heldout.iloc[i][
                    "original_dataset_index"
                ]
            )


            # ================================================
            # RANDOM FOREST
            # ================================================

            prediction = int(
                model.predict(
                    sample
                )[0]
            )

            confidence = float(
                max(
                    model.predict_proba(
                        sample
                    )[0]
                )
            )


            # ================================================
            # THREAT ASSESSMENT
            # ================================================

            assessment = (
                assessment_engine.assess(
                    prediction=prediction,
                    confidence=confidence
                )
            )

            score = assessment[
                "threat_score"
            ]

            severity = assessment[
                "severity"
            ]

            severities[
                severity
            ] += 1


            # ================================================
            # PATTERN RECOGNITION
            # ================================================

            pattern = None

            pattern_status = (
                "NOT_ANALYZED"
            )

            pattern_id = None
            fingerprint = None

            prior_occurrences = 0

            previous_action = None
            previous_response = None
            previous_successes = 0


            if prediction == 1:

                features = {
                    key: float(row[key])
                    for key in PATTERN_FEATURES
                    if (
                        key in X.columns
                        and pd.notna(row[key])
                    )
                }

                pattern = (
                    pattern_engine.analyze(
                        prediction=prediction,
                        confidence=confidence,
                        threat_score=score,
                        severity=severity,
                        features=features,
                    )
                )

                pattern_status = (
                    pattern[
                        "pattern_status"
                    ]
                )

                pattern_id = (
                    pattern[
                        "pattern_id"
                    ]
                )

                fingerprint = (
                    pattern[
                        "fingerprint"
                    ]
                )

                prior_occurrences = (
                    pattern[
                        "occurrence_count"
                    ]
                )

                previous_action = (
                    pattern.get(
                        "previous_action"
                    )
                )

                previous_response = (
                    pattern.get(
                        "previous_response"
                    )
                )

                previous_successes = int(
                    pattern.get(
                        "previous_successful_containments",
                        0
                    )
                    or 0
                )

                patterns[
                    pattern_status
                ] += 1


            # ================================================
            # FROZEN RL DECISION
            # ================================================

            state = agent.get_state(
                prediction,
                confidence
            )

            unseen_state = (
                state not in agent.q_table
            )


            if unseen_state:

                # Conservative unknown-state handling.
                action = "ALERT"

                metrics[
                    "unseen_rl_states"
                ] += 1

            else:

                action = (
                    agent.choose_action(
                        state,
                        training=False
                    )
                )


            actions[
                action
            ] += 1


            # ================================================
            # INITIAL RESPONSE
            # ================================================

            primary = (
                response_engine.execute(
                    action,
                    severity
                )
            )


            # ================================================
            # OFFLINE VERIFICATION
            # ================================================

            initial_check = verify(
                verifier,
                action,
                primary["response"],
                prediction,
                severity,
                truth
            )


            if initial_check[
                "containment_success"
            ]:

                metrics[
                    "initial_simulated_containments"
                ] += 1


            if truth == 1:

                metrics[
                    "actual_attacks"
                ] += 1

                if action == "ALLOW":

                    metrics[
                        "initial_missed_attacks"
                    ] += 1

                if action == "ALERT":

                    metrics[
                        "initial_alert_only_attacks"
                    ] += 1


            if (
                truth == 0
                and action == "BLOCK"
            ):

                metrics[
                    "initial_false_blocks"
                ] += 1


            if (
                truth == 0
                and action == "ALERT"
            ):

                metrics[
                    "initial_unnecessary_alerts"
                ] += 1


            # ================================================
            # ORACLE-ASSISTED HEALING INPUT
            # ================================================

            healing_prediction = (
                1
                if (
                    truth == 1
                    and initial_check[
                        "recovery_required"
                    ]
                )
                else prediction
            )


            healing_severity = (
                "HIGH"
                if (
                    truth == 1
                    and prediction == 0
                )
                else severity
            )


            # ================================================
            # SELF-HEALING DECISION
            # ================================================

            healing = healer.heal(
                prediction=healing_prediction,
                severity=healing_severity,
                current_action=action,
                verification_result=initial_check,
                pattern_status=pattern_status,
                occurrence_count=prior_occurrences,
                previous_action=previous_action,
                previous_successful_containments=(
                    previous_successes
                ),
            )


            if (
                healing.get(
                    "healing_action"
                )
                == "REUSE_DEFENSE"
            ):

                metrics[
                    "reused_defense_decisions"
                ] += 1


            # ================================================
            # RECOVERY
            # ================================================

            recommended = (
                healing.get(
                    "recommended_action"
                )
            )

            recovery_action = None
            recovery_response = None
            recovery_check = None

            recovery_state = (
                "NOT_REQUIRED"
            )


            if (
                initial_check[
                    "recovery_required"
                ]
                and truth == 1
            ):

                metrics[
                    "recovery_recommended"
                ] += 1


                if (
                    recommended
                    in {
                        "ALLOW",
                        "ALERT",
                        "BLOCK"
                    }
                    and recommended != action
                ):

                    recovery_action = (
                        recommended
                    )

                    recovery_response = (
                        response_engine.execute(
                            recovery_action,
                            healing_severity
                        )
                    )

                    recovery_check = verify(
                        verifier,
                        recovery_action,
                        recovery_response[
                            "response"
                        ],
                        healing_prediction,
                        healing_severity,
                        truth
                    )

                    metrics[
                        "recovery_actions_executed"
                    ] += 1


                    if recovery_check[
                        "containment_success"
                    ]:

                        recovery_state = (
                            "SIMULATED_SUCCESS"
                        )

                        metrics[
                            "successful_simulated_recoveries"
                        ] += 1

                    else:

                        recovery_state = (
                            "NOT_CONTAINED"
                        )

                        metrics[
                            "unsuccessful_recoveries"
                        ] += 1


                else:

                    recovery_state = (
                        "ESCALATION_REQUIRED_NOT_EXECUTED"
                    )

                    metrics[
                        "unexecuted_escalations"
                    ] += 1


            # ================================================
            # FINAL CONTAINMENT
            # ================================================

            final_containment = bool(
                initial_check[
                    "containment_success"
                ]
                or (
                    recovery_check
                    and recovery_check[
                        "containment_success"
                    ]
                )
            )


            if (
                truth == 1
                and final_containment
            ):

                metrics[
                    "post_recovery_simulated_containments"
                ] += 1


            if (
                truth == 1
                and not final_containment
            ):

                metrics[
                    "attacks_remaining_uncontained"
                ] += 1


            # ================================================
            # EVENT ID
            # ================================================

            event_id = (
                f"HOLDOUT-"
                f"{RUN_ID}-"
                f"{i:04d}"
            )


            # ================================================
            # RECOVERY AUDIT
            # ================================================

            if (
                truth == 1
                and initial_check[
                    "recovery_required"
                ]
            ):

                memory.store_recovery_audit(
                    event_id=event_id,
                    run_id=RUN_ID,
                    flow_step=i,
                    original_prediction=prediction,
                    true_label=truth,
                    initial_action=action,
                    initial_verification_status=(
                        initial_check[
                            "verification_status"
                        ]
                    ),
                    healing_action=(
                        healing[
                            "healing_action"
                        ]
                    ),
                    recovery_action=recovery_action,
                    recovery_status=recovery_state,
                    recovery_verified=bool(
                        recovery_check
                        and recovery_check[
                            "containment_success"
                        ]
                    ),
                    metadata={
                        "original_dataset_index":
                            original_index,
                        "original_severity":
                            severity,
                        "healing_severity":
                            healing_severity,
                        "oracle_assisted":
                            True,
                        "initially_detected_by_rf":
                            prediction == 1,
                        "evaluation_set":
                            "RL_HELD_OUT",
                    },
                )

                metrics[
                    "recovery_audit_records"
                ] += 1


            # ================================================
            # THREAT MEMORY
            # ================================================

            if prediction == 1:

                effective_action = (
                    recovery_action
                    or action
                )

                effective_response = (
                    recovery_response[
                        "response"
                    ]
                    if recovery_response
                    else primary[
                        "response"
                    ]
                )


                if pattern_status == "NEW":

                    memory.create_pattern(
                        pattern_id=pattern_id,
                        fingerprint=fingerprint,
                        prediction=prediction,
                        confidence=confidence,
                        threat_score=score,
                        severity=severity,
                        action=effective_action,
                        response=effective_response,
                        containment_success=False,
                    )

                else:

                    memory.update_pattern(
                        pattern_id=pattern_id,
                        confidence=confidence,
                        threat_score=score,
                        severity=severity,
                        action=effective_action,
                        response=effective_response,
                        containment_success=False,
                    )


                memory.store_event(
                    event_id=event_id,
                    prediction=prediction,
                    confidence=confidence,
                    threat_score=score,
                    severity=severity,
                    rl_state=state,
                    rl_action=action,
                    response=primary[
                        "response"
                    ],
                    containment=bool(
                        primary[
                            "containment"
                        ]
                    ),
                    containment_verified=False,
                    fingerprint=fingerprint,
                    pattern_id=pattern_id,
                    pattern_status=pattern_status,
                    metadata={
                        "dataset":
                            "CIC-IDS2017",
                        "original_dataset_index":
                            original_index,
                        "run_id":
                            RUN_ID,
                        "evaluation_mode":
                            "RL_HELD_OUT_ORACLE_ASSISTED",
                        "true_label":
                            truth,
                        "initial_verification":
                            initial_check,
                        "healing":
                            healing,
                        "recovery_action":
                            recovery_action,
                        "recovery_verification":
                            recovery_check,
                        "recovery_state":
                            recovery_state,
                        "behavior_profile":
                            pattern.get(
                                "behavior_profile"
                            ),
                        "pattern_signature":
                            pattern.get(
                                "pattern_signature"
                            ),
                    },
                )


                if (
                    action == "BLOCK"
                    or recovery_action == "BLOCK"
                ):

                    memory.record_containment_verification(
                        event_id=event_id,
                        pattern_id=pattern_id,
                        success=final_containment,
                    )

                    metrics[
                        "persisted_block_attempts"
                    ] += 1


            # ================================================
            # FROZEN RL REWARD
            # ================================================

            reward = get_reward(
                true_label=truth,
                action=action
            )

            cumulative_reward += reward

            reward_curve.append(
                cumulative_reward
            )


            # ================================================
            # EVENT OUTPUT
            # ================================================

            events.append({

                "run_id":
                    RUN_ID,

                "event_id":
                    event_id,

                "step":
                    i,

                "original_dataset_index":
                    original_index,

                "training_overlap":
                    original_index
                    in training_index_set,

                "true_label":
                    truth,

                "prediction":
                    prediction,

                "confidence":
                    round(
                        confidence,
                        4
                    ),

                "threat_score":
                    score,

                "severity":
                    severity,

                "rl_state":
                    str(state),

                "unseen_rl_state":
                    unseen_state,

                "initial_action":
                    action,

                "initial_response":
                    primary["response"],

                "initial_verification":
                    initial_check[
                        "verification_status"
                    ],

                "initial_simulated_containment":
                    initial_check[
                        "containment_success"
                    ],

                "recovery_required":
                    initial_check[
                        "recovery_required"
                    ],

                "healing_action":
                    healing[
                        "healing_action"
                    ],

                "recommended_action":
                    recommended,

                "recovery_action":
                    recovery_action,

                "recovery_status":
                    recovery_state,

                "post_recovery_simulated_containment":
                    final_containment,

                "pattern_status":
                    pattern_status,

                "pattern_id":
                    pattern_id,

                "reward":
                    reward,
            })


            if i % 300 == 0:

                print(
                    f"Step {i:4d} | "
                    f"RF={prediction} "
                    f"truth={truth} "
                    f"RL={action:5s} "
                    f"verify="
                    f"{initial_check['verification_status']:20s} "
                    f"heal="
                    f"{healing['healing_action']:14s} "
                    f"recovery="
                    f"{recovery_state}"
                )


        stats = (
            memory.get_statistics()
        )


    finally:

        memory.close()


    # ========================================================
    # DATAFRAME
    # ========================================================

    events_df = pd.DataFrame(
        events
    )


    # ========================================================
    # FINAL LEAKAGE CHECK
    # ========================================================

    csv_overlap = int(
        events_df[
            "training_overlap"
        ].sum()
    )

    if csv_overlap != 0:

        raise RuntimeError(
            f"HELD-OUT VALIDATION FAILED: "
            f"{csv_overlap} training rows "
            f"found in output."
        )


    # ========================================================
    # SAVE EVENTS
    # ========================================================

    events_df.to_csv(
        RUN_DIR / "heldout_self_healing_events.csv",
        index=False
    )


    # ========================================================
    # ML METRICS
    # ========================================================

    tp = int(
        (
            (events_df["true_label"] == 1)
            &
            (events_df["prediction"] == 1)
        ).sum()
    )

    tn = int(
        (
            (events_df["true_label"] == 0)
            &
            (events_df["prediction"] == 0)
        ).sum()
    )

    fp = int(
        (
            (events_df["true_label"] == 0)
            &
            (events_df["prediction"] == 1)
        ).sum()
    )

    fn = int(
        (
            (events_df["true_label"] == 1)
            &
            (events_df["prediction"] == 0)
        ).sum()
    )


    accuracy = percent(
        tp + tn,
        len(events_df)
    )

    precision = percent(
        tp,
        tp + fp
    )

    recall = percent(
        tp,
        tp + fn
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    summary = {

        "run_id":
            RUN_ID,

        "evaluation_mode":
            "RL_HELD_OUT_ORACLE_ASSISTED",

        "total_samples":
            len(events_df),

        "excluded_rl_training_rows":
            len(training_index_set),

        "training_overlap":
            csv_overlap,

        "true_attacks":
            metrics["actual_attacks"],

        "true_benign":
            len(events_df)
            - metrics["actual_attacks"],

        "ml_tp":
            tp,

        "ml_tn":
            tn,

        "ml_fp":
            fp,

        "ml_fn":
            fn,

        "ml_accuracy_percent":
            round(
                accuracy,
                2
            ),

        "ml_precision_percent":
            round(
                precision,
                2
            ),

        "ml_recall_percent":
            round(
                recall,
                2
            ),

        "ml_f1_percent":
            round(
                f1,
                2
            ),

        "allow_count":
            actions["ALLOW"],

        "alert_count":
            actions["ALERT"],

        "block_count":
            actions["BLOCK"],

        "unseen_rl_states":
            metrics[
                "unseen_rl_states"
            ],

        "initial_missed_attacks":
            metrics[
                "initial_missed_attacks"
            ],

        "initial_alert_only_attacks":
            metrics[
                "initial_alert_only_attacks"
            ],

        "initial_false_blocks":
            metrics[
                "initial_false_blocks"
            ],

        "initial_unnecessary_alerts":
            metrics[
                "initial_unnecessary_alerts"
            ],

        "actual_attacks":
            metrics[
                "actual_attacks"
            ],

        "initial_simulated_containments":
            metrics[
                "initial_simulated_containments"
            ],

        "recovery_actions_executed":
            metrics[
                "recovery_actions_executed"
            ],

        "successful_simulated_recoveries":
            metrics[
                "successful_simulated_recoveries"
            ],

        "unsuccessful_recoveries":
            metrics[
                "unsuccessful_recoveries"
            ],

        "unexecuted_escalations":
            metrics[
                "unexecuted_escalations"
            ],

        "post_recovery_simulated_containments":
            metrics[
                "post_recovery_simulated_containments"
            ],

        "attacks_remaining_uncontained":
            metrics[
                "attacks_remaining_uncontained"
            ],

        "initial_containment_rate_percent":
            round(
                percent(
                    metrics[
                        "initial_simulated_containments"
                    ],
                    metrics[
                        "actual_attacks"
                    ]
                ),
                2
            ),

        "post_recovery_containment_rate_percent":
            round(
                percent(
                    metrics[
                        "post_recovery_simulated_containments"
                    ],
                    metrics[
                        "actual_attacks"
                    ]
                ),
                2
            ),

        "recovery_audit_records":
            stats[
                "recovery_audit_events"
            ],

        "verified_recovery_audits":
            stats[
                "verified_recoveries"
            ],

        "stored_threat_events":
            stats[
                "total_events"
            ],

        "unique_patterns":
            stats[
                "total_patterns"
            ],

        "repeated_patterns":
            stats[
                "repeated_patterns"
            ],

        "defense_reuse_decisions":
            metrics[
                "reused_defense_decisions"
            ],

        "total_reward":
            cumulative_reward,
    }


    summary["evaluation_set"] = "HELDOUT_PHASE4C5"
    summary["data_scope_note"] = (
        "Rows exclude the 2,000 RL training rows (0 overlap). About 1% of "
        "rows may fall in the Random Forest training split, whose seed was "
        "not fixed."
    )
    summary["database_scope"] = "PER_RUN_FRESH_DATABASE"

    pd.DataFrame(
        [summary]
    ).to_csv(
        RUN_DIR / "heldout_self_healing_summary.csv",
        index=False
    )

    with open(
        RUN_DIR / "heldout_self_healing_summary.json", "w", encoding="utf-8"
    ) as handle:
        json.dump(summary, handle, indent=2, default=str)


    # ========================================================
    # TERMINAL RESULTS
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "HELD-OUT SELF-HEALING RESULTS"
    )

    print(
        "=" * 78
    )

    print(
        f"Samples: {len(events_df)}"
    )

    print(
        f"RL training overlap: "
        f"{csv_overlap}"
    )

    print(
        "\nML PERFORMANCE"
    )

    print(
        f"TP={tp} | TN={tn} | "
        f"FP={fp} | FN={fn}"
    )

    print(
        f"Accuracy : {accuracy:.2f}%"
    )

    print(
        f"Precision: {precision:.2f}%"
    )

    print(
        f"Recall   : {recall:.2f}%"
    )

    print(
        f"F1       : {f1:.2f}%"
    )


    print(
        "\nINITIAL FROZEN RL RESPONSE"
    )

    print(
        f"Actions: {dict(actions)}"
    )

    print(
        f"Unseen RL states: "
        f"{metrics['unseen_rl_states']}"
    )

    print(
        f"Missed attacks: "
        f"{metrics['initial_missed_attacks']}"
    )

    print(
        f"Alert-only attacks: "
        f"{metrics['initial_alert_only_attacks']}"
    )

    print(
        f"False blocks: "
        f"{metrics['initial_false_blocks']}"
    )

    print(
        f"Unnecessary benign alerts: "
        f"{metrics['initial_unnecessary_alerts']}"
    )


    print(
        "\nSELF-HEALING"
    )

    print(
        f"Ground-truth attacks: "
        f"{metrics['actual_attacks']}"
    )

    print(
        f"Initially simulated-contained: "
        f"{metrics['initial_simulated_containments']}"
    )

    print(
        f"Recovery actions executed: "
        f"{metrics['recovery_actions_executed']}"
    )

    print(
        f"Successful simulated recoveries: "
        f"{metrics['successful_simulated_recoveries']}"
    )

    print(
        f"Remaining uncontained: "
        f"{metrics['attacks_remaining_uncontained']}"
    )

    print(
        f"Initial containment rate: "
        f"{summary['initial_containment_rate_percent']:.2f}%"
    )

    print(
        f"Post-recovery containment rate: "
        f"{summary['post_recovery_containment_rate_percent']:.2f}%"
    )


    print(
        "\nTHREAT MEMORY"
    )

    print(
        f"Stored predicted threats: "
        f"{stats['total_events']}"
    )

    print(
        f"Unique patterns: "
        f"{stats['total_patterns']}"
    )

    print(
        f"Repeated patterns: "
        f"{stats['repeated_patterns']}"
    )

    print(
        f"Recovery audit records: "
        f"{stats['recovery_audit_events']}"
    )

    print(
        f"Verified recoveries: "
        f"{stats['verified_recoveries']}"
    )


    print(
        "\nIMPORTANT:"
    )

    print(
        "Held-out refers to exclusion from "
        "RL training rows."
    )

    print(
        "Recovery is still oracle-assisted "
        "offline evaluation."
    )

    print(
        "These results do NOT represent "
        "live autonomous containment."
    )

    print(
        "=" * 78
    )


    # ========================================================
    # CHART — BEFORE VS AFTER SELF-HEALING
    # ========================================================

    contained_before = (
        metrics[
            "initial_simulated_containments"
        ]
    )

    uncontained_before = (
        metrics["actual_attacks"]
        - contained_before
    )

    contained_after = (
        metrics[
            "post_recovery_simulated_containments"
        ]
    )

    uncontained_after = (
        metrics["actual_attacks"]
        - contained_after
    )


    plt.figure(
        figsize=(8, 5)
    )

    labels = [
        "Initial Response",
        "After Recovery"
    ]

    contained = [
        contained_before,
        contained_after
    ]

    uncontained = [
        uncontained_before,
        uncontained_after
    ]


    plt.bar(
        labels,
        contained,
        label="Simulated Contained"
    )

    plt.bar(
        labels,
        uncontained,
        bottom=contained,
        label="Not Contained"
    )

    plt.title(
        "Held-Out Offline Self-Healing Evaluation"
    )

    plt.ylabel(
        "Ground-Truth Attacks"
    )

    plt.legend()

    plt.tight_layout()

    plt.savefig(
        RUN_DIR / "heldout_self_healing_comparison.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


    # ========================================================
    # CHART — CUMULATIVE FROZEN POLICY REWARD
    # ========================================================

    plt.figure(
        figsize=(10, 5)
    )

    plt.plot(
        reward_curve,
        linewidth=2
    )

    plt.title(
        "Held-Out Frozen RL Policy Cumulative Reward"
    )

    plt.xlabel(
        "Held-Out Flow Step"
    )

    plt.ylabel(
        "Cumulative Reward"
    )

    plt.grid(
        alpha=0.3
    )

    plt.tight_layout()

    plt.savefig(
        RUN_DIR / "heldout_rl_reward_curve.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


    print(
        "\nOutputs generated:"
    )

    print(
        "1. heldout_self_healing_events.csv"
    )

    print(
        "2. heldout_self_healing_summary.csv"
    )

    print(
        "3. heldout_self_healing_comparison.png"
    )

    print(
        "4. heldout_rl_reward_curve.png"
    )

    print(
        f"5. {THREAT_MEMORY_FILE.name}"
    )

    print(f"\nAll outputs saved in: {RUN_DIR}")


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()