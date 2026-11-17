"""
Phase 4 offline self-healing evaluation.

IMPORTANT:

Ground truth is used ONLY after the initial RL action for
oracle-assisted offline verification and recovery evaluation.

This is NOT a live autonomous containment demonstration.

No real firewall rules are applied.
"""

import argparse
import json
import sys
from collections import Counter

import joblib
import matplotlib

matplotlib.use("Agg")  # charts are saved to files; no GUI window needed

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

MODEL_FILE = cfg.MODEL_FILE

Q_TABLE_FILE = cfg.Q_TABLE_FILE

DATA_PATH = cfg.DATA_PATH

SAMPLE_SIZE = 2000

RANDOM_STATE = 42

RUN_ID = cfg.new_run_id()

# Every output of this run lives in runs/<RUN_ID>/.
# The threat-memory database is created FRESH inside that folder, so
# database statistics are scoped to this run only. Historical databases
# (test_phase4_audit.db etc.) are never opened or modified.
RUN_DIR = None          # set in main()
THREAT_MEMORY_FILE = None


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

def percent(
    numerator,
    denominator
):

    if denominator == 0:

        return 0.0

    return (
        100.0
        * numerator
        / denominator
    )


# ============================================================
# RESPONSE VERIFICATION WRAPPER
# ============================================================

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

        true_label=truth
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def parse_args(argv=None):

    parser = argparse.ArgumentParser(
        description="Phase 4 offline self-healing evaluation"
    )

    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Generate the dashboard but do not open it."
    )

    parser.add_argument(
        "--sample-size",
        type=int,
        default=SAMPLE_SIZE,
        help=(
            "Number of flows (default 2000 = the standard Phase 4 "
            "evaluation). Smaller values are for smoke tests only."
        )
    )

    parser.add_argument(
        "--skip-endpoint-demo",
        action="store_true",
        help="Do not run the controlled endpoint-healing demonstration."
    )

    parser.add_argument(
        "--skip-apt-demo",
        action="store_true",
        help="Do not run the controlled multi-stage APT campaign simulation."
    )

    return parser.parse_args(argv)


def main(argv=None):

    global RUN_DIR, THREAT_MEMORY_FILE

    args = parse_args(argv)

    missing = cfg.check_inputs()

    if missing:

        print("\nERROR: required input files are missing:")

        for path in missing:
            print("  -", path)

        sys.exit(1)

    RUN_DIR = cfg.create_run_dir(RUN_ID)

    THREAT_MEMORY_FILE = RUN_DIR / "threat_memory_run.db"

    print(f"\nRun folder: {RUN_DIR}")

    # ========================================================
    # LOAD MODELS
    # ========================================================

    print(
        "\nLoading RF model, frozen RL policy, "
        "and CIC-IDS2017..."
    )


    model = joblib.load(
        MODEL_FILE
    )


    agent = RLAgent()

    agent.load_q_table(
        Q_TABLE_FILE
    )

    agent.set_evaluation_mode()


    # ========================================================
    # INITIALIZE MODULES
    # ========================================================

    assessment_engine = (
        ThreatAssessment()
    )

    response_engine = (
        ResponseEngine()
    )

    verifier = (
        ResponseVerifier()
    )

    healer = (
        SelfHealingEngine()
    )


    # ========================================================
    # LOAD DATASET
    # ========================================================

    df = pd.read_parquet(
        DATA_PATH
    )


    df["target"] = df["Label"].apply(

        lambda x:

        0
        if x == "Benign"
        else 1
    )


    sampled = df.sample(

        n=args.sample_size,

        random_state=RANDOM_STATE

    ).reset_index(
        drop=True
    )


    X = sampled.drop(

        columns=[
            "Label",
            "ClassLabel",
            "target"
        ],

        errors="ignore"
    )


    y = sampled[
        "target"
    ].to_numpy()


    # ========================================================
    # RUN STORAGE
    # ========================================================

    events = []

    # Actual attacks from THIS run that needed recovery. Used later as
    # the triggering incidents for the controlled endpoint-healing demo.
    recovery_incidents = []

    reward_curve = []

    cumulative_reward = 0


    actions = Counter()

    severities = Counter()

    patterns = Counter()

    metrics = Counter()


    # ========================================================
    # HEADER
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "PHASE 4: OFFLINE SELF-HEALING "
        "EVALUATION (ORACLE-ASSISTED)"
    )

    print(
        "=" * 76
    )


    print(
        f"Run ID: {RUN_ID} | "
        f"Samples: {len(X)} | "
        f"Q states: {len(agent.q_table)}"
    )


    print(
        "SIMULATED only: no real firewall or "
        "live containment telemetry.\n"
    )


    # ========================================================
    # INITIALIZE THREAT MEMORY
    # ========================================================

    memory = ThreatMemory(
        THREAT_MEMORY_FILE
    )


    try:

        pattern_engine = PatternEngine(
            memory
        )


        # ====================================================
        # PROCESS FLOWS
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


            # ================================================
            # STEP 1 — RANDOM FOREST DETECTION
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
            # STEP 2 — THREAT ASSESSMENT
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
            # STEP 3 — PATTERN RECOGNITION
            # ================================================
            #
            # IMPORTANT:
            #
            # Pattern recognition happens BEFORE oracle
            # ground truth is used.
            #
            # Therefore only RF-predicted threats enter
            # threat pattern recognition.
            #
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

                    key:
                        float(
                            row[key]
                        )

                    for key
                    in PATTERN_FEATURES

                    if (
                        key in X.columns
                        and pd.notna(
                            row[key]
                        )
                    )
                }


                pattern = (
                    pattern_engine.analyze(

                        prediction=prediction,

                        confidence=confidence,

                        threat_score=score,

                        severity=severity,

                        features=features
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
            # STEP 4 — RL STATE
            # ================================================

            state = agent.get_state(

                prediction,

                confidence
            )


            unseen_state = (
                state
                not in agent.q_table
            )


            # ================================================
            # STEP 5 — RL DECISION
            # ================================================

            if unseen_state:

                # Conservative fallback.
                #
                # We deliberately avoid the Q-table
                # zero-value tie defaulting to ALLOW.

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
            # STEP 6 — PRIMARY RESPONSE
            # ================================================

            primary = (
                response_engine.execute(

                    action,

                    severity
                )
            )


            # ================================================
            # STEP 7 — OFFLINE VERIFICATION
            # ================================================
            #
            # Ground truth enters ONLY HERE.
            #
            # ================================================

            initial_check = verify(

                verifier,

                action,

                primary[
                    "response"
                ],

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
            # STEP 8 — SELF-HEALING DECISION
            # ================================================
            #
            # IMPORTANT:
            #
            # For an RF false negative, the offline evaluator
            # now knows from ground truth that the flow was an
            # attack.
            #
            # We therefore use an ORACLE OVERRIDE only for the
            # recovery experiment.
            #
            # This is NOT deployable live behaviour.
            #
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
                )
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
            # STEP 9 — RECOVERY
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
            # STEP 10 — FINAL CONTAINMENT RESULT
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
            # STEP 11 — GENERATE EVENT ID
            # ================================================

            event_id = (

                f"EVT-"
                f"{RUN_ID}-"
                f"{i:04d}"
            )


            # ================================================
            # STEP 12 — RECOVERY AUDIT LOG
            # ================================================
            #
            # Store any actual attack that required recovery.
            #
            # This includes:
            #
            # - RF false negatives
            # - alert-only attacks
            # - failed initial containment
            #
            # It is stored separately from threat_patterns.
            #
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

                    original_prediction=(
                        prediction
                    ),

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

                    recovery_action=(
                        recovery_action
                    ),

                    recovery_status=(
                        recovery_state
                    ),

                    recovery_verified=bool(

                        recovery_check

                        and recovery_check[
                            "containment_success"
                        ]
                    ),

                    metadata={

                        "original_severity":
                            severity,

                        "healing_severity":
                            healing_severity,

                        "oracle_assisted":
                            True,

                        "initially_detected_by_rf":
                            prediction == 1,

                        "initial_verification":
                            initial_check,

                        "recovery_verification":
                            recovery_check
                    }
                )


                metrics[
                    "recovery_audit_records"
                ] += 1

                recovery_incidents.append({
                    "event_id": event_id,
                    "flow_step": i,
                    "original_prediction": prediction,
                    "true_label": truth,
                    "initial_action": action,
                    "severity": severity,
                    "healing_severity": healing_severity,
                    "healing_action": healing["healing_action"],
                    "recommended_action": recommended,
                    "recovery_action": recovery_action,
                    "recovery_status": recovery_state,
                })


            # ================================================
            # STEP 13 — PERSIST RF-DETECTED THREAT
            # ================================================
            #
            # Only RF-predicted threats enter threat memory
            # and pattern history.
            #
            # Oracle-discovered false negatives are NOT
            # retroactively represented as RF detections.
            #
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


                if (
                    pattern_status
                    == "NEW"
                ):

                    memory.create_pattern(

                        pattern_id=pattern_id,

                        fingerprint=fingerprint,

                        prediction=prediction,

                        confidence=confidence,

                        threat_score=score,

                        severity=severity,

                        action=effective_action,

                        response=effective_response,

                        containment_success=False
                    )


                else:

                    memory.update_pattern(

                        pattern_id=pattern_id,

                        confidence=confidence,

                        threat_score=score,

                        severity=severity,

                        action=effective_action,

                        response=effective_response,

                        containment_success=False
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

                        "run_id":
                            RUN_ID,

                        "evaluation_mode":
                            "OFFLINE_ORACLE_ASSISTED",

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
                            )
                    }
                )


                # ============================================
                # RECORD VERIFIED CONTAINMENT
                # ============================================

                if (

                    action == "BLOCK"

                    or recovery_action
                    == "BLOCK"
                ):

                    memory.record_containment_verification(

                        event_id=event_id,

                        pattern_id=pattern_id,

                        success=final_containment
                    )


                    metrics[
                        "persisted_block_attempts"
                    ] += 1


                    if final_containment:

                        metrics[
                            "persisted_simulated_successes"
                        ] += 1


                    else:

                        metrics[
                            "persisted_simulated_failures"
                        ] += 1


            # ================================================
            # STEP 14 — RL REWARD
            # ================================================

            reward = get_reward(

                true_label=truth,

                action=action
            )


            cumulative_reward += (
                reward
            )


            reward_curve.append(
                cumulative_reward
            )


            # ================================================
            # STEP 15 — CSV EVENT
            # ================================================

            events.append({

                "run_id":
                    RUN_ID,

                "event_id":
                    event_id,

                "step":
                    i,

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

                "state":
                    str(
                        state
                    ),

                "unseen_rl_state":
                    unseen_state,

                "action":
                    action,

                "response":
                    primary[
                        "response"
                    ],

                "status":
                    primary[
                        "status"
                    ],

                "containment_action":
                    bool(
                        primary[
                            "containment"
                        ]
                    ),

                "initial_verification_status":
                    initial_check[
                        "verification_status"
                    ],

                "initial_verification_type":
                    initial_check[
                        "verification_type"
                    ],

                "initial_response_verified":
                    initial_check[
                        "verified"
                    ],

                "initial_simulated_containment":
                    initial_check[
                        "containment_success"
                    ],

                "initial_recovery_required":
                    initial_check[
                        "recovery_required"
                    ],

                "healing_status":
                    healing[
                        "healing_status"
                    ],

                "healing_action":
                    healing[
                        "healing_action"
                    ],

                "policy_update":
                    healing[
                        "policy_update"
                    ],

                "recommended_action":
                    recommended,

                "recovery_action":
                    recovery_action,

                "recovery_response":
                    (
                        recovery_response[
                            "response"
                        ]

                        if recovery_response

                        else None
                    ),

                "recovery_status":
                    recovery_state,

                "recovery_verification_status":
                    (
                        recovery_check[
                            "verification_status"
                        ]

                        if recovery_check

                        else None
                    ),

                "post_recovery_simulated_containment":
                    final_containment,

                "oracle_assisted_recovery":
                    bool(
                        recovery_action
                    ),

                "recovery_audit_recorded":
                    bool(

                        truth == 1

                        and initial_check[
                            "recovery_required"
                        ]
                    ),

                "pattern_status":
                    pattern_status,

                "pattern_id":
                    pattern_id,

                "fingerprint":
                    fingerprint,

                "pattern_occurrences_before_event":
                    prior_occurrences,

                "previous_action":
                    previous_action,

                "previous_response":
                    previous_response,

                "previous_successful_containments":
                    previous_successes,

                "reward":
                    reward
            })


            # ================================================
            # PROGRESS
            # ================================================

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


        # ====================================================
        # MEMORY STATISTICS
        # ====================================================

        stats = (
            memory.get_statistics()
        )


    finally:

        memory.close()


    # ========================================================
    # SAVE SECURITY EVENTS
    # ========================================================

    events_df = pd.DataFrame(
        events
    )


    events_df.to_csv(

        RUN_DIR / "security_events.csv",

        index=False
    )


    # ========================================================
    # PIPELINE SUMMARY
    # ========================================================

    # Record zero counts explicitly, so a metric that never occurred
    # appears as 0 instead of being silently absent from the summary.
    for key in [
        "unseen_rl_states", "initial_missed_attacks",
        "initial_alert_only_attacks", "initial_false_blocks",
        "initial_unnecessary_alerts", "recovery_recommended",
        "recovery_actions_executed", "successful_simulated_recoveries",
        "unsuccessful_recoveries", "unexecuted_escalations",
        "attacks_remaining_uncontained", "reused_defense_decisions",
        "recovery_audit_records",
    ]:
        metrics[key] += 0

    summary = {

        "run_id":
            RUN_ID,

        "evaluation_mode":
            "OFFLINE_ORACLE_ASSISTED",

        "evaluation_set":
            (
                "STANDARD_PHASE4"
                if args.sample_size == SAMPLE_SIZE
                else "SMOKE_TEST"
            ),

        "data_scope_note":
            (
                "Standard Phase 4 sample (random_state=42). These rows "
                "are also the RL training sample and lie inside the "
                "Random Forest's 100k training sample, so ML and RL "
                "figures here are in-sample. Use held-out Phase 4C.5 "
                "for generalisation claims."
            ),

        "database_scope":
            "PER_RUN_FRESH_DATABASE",

        "total_samples":
            len(X),

        "total_reward":
            cumulative_reward,

        "allow_count":
            actions["ALLOW"],

        "alert_count":
            actions["ALERT"],

        "block_count":
            actions["BLOCK"],

        "false_negative":
            metrics[
                "initial_missed_attacks"
            ],

        "false_positive":
            metrics[
                "initial_false_blocks"
            ],

        "allow_risk_percent":
            round(

                percent(

                    metrics[
                        "initial_missed_attacks"
                    ],

                    actions[
                        "ALLOW"
                    ]
                ),

                2
            ),

        "block_risk_percent":
            round(

                percent(

                    metrics[
                        "initial_false_blocks"
                    ],

                    actions[
                        "BLOCK"
                    ]
                ),

                2
            ),

        "alert_attack_ratio":
            round(

                percent(

                    metrics[
                        "initial_alert_only_attacks"
                    ],

                    actions[
                        "ALERT"
                    ]
                ),

                2
            ),

        "low":
            severities["LOW"],

        "medium":
            severities["MEDIUM"],

        "high":
            severities["HIGH"],

        "critical":
            severities["CRITICAL"],

        "q_table_states":
            len(
                agent.q_table
            ),

        "patterns_analyzed":
            sum(
                patterns.values()
            ),

        "new_pattern_events":
            patterns["NEW"],

        "known_pattern_events":
            patterns["KNOWN"],

        "repeated_pattern_events":
            patterns["REPEATED"],

        "stored_threat_events":
            stats[
                "total_events"
            ],

        "unique_threat_patterns":
            stats[
                "total_patterns"
            ],

        "recurring_threat_patterns":
            stats[
                "repeated_patterns"
            ],

        "containment_actions":
            int(

                events_df[
                    "containment_action"
                ].sum()
            ),

        "verified_containments":
            stats[
                "successful_containments"
            ],

        "verified_events":
            stats[
                "verified_events"
            ],

        "historical_failed_containments":
            stats[
                "failed_containments"
            ],

        "recovery_audit_events":
            stats[
                "recovery_audit_events"
            ],

        "verified_recoveries":
            stats[
                "verified_recoveries"
            ],

        **dict(
            metrics
        ),

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
            )
    }


    pd.DataFrame(
        [summary]
    ).to_csv(

        RUN_DIR / "pipeline_summary.csv",

        index=False
    )


    # ========================================================
    # RESULTS
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "PHASE 4 OFFLINE RESULTS — "
        "NOT LIVE CONTAINMENT"
    )

    print(
        "=" * 76
    )


    print(
        f"Samples: {len(X)} | "
        f"True attacks: "
        f"{metrics['actual_attacks']}"
    )


    print(
        f"Initial RL actions: "
        f"{dict(actions)} | "
        f"Frozen-policy reward: "
        f"{cumulative_reward}"
    )


    print(
        f"Initial missed attacks: "
        f"{metrics['initial_missed_attacks']}"
    )


    print(
        f"Initial alert-only attacks: "
        f"{metrics['initial_alert_only_attacks']}"
    )


    print(
        f"Initial false blocks: "
        f"{metrics['initial_false_blocks']}"
    )


    print(
        f"Initial simulated containments: "
        f"{metrics['initial_simulated_containments']}"
    )


    print(
        f"Recovery actions executed "
        f"(oracle-assisted): "
        f"{metrics['recovery_actions_executed']}"
    )


    print(
        f"Successful simulated recoveries: "
        f"{metrics['successful_simulated_recoveries']}"
    )


    print(
        f"Unexecuted escalations: "
        f"{metrics['unexecuted_escalations']}"
    )


    print(
        f"Attacks uncontained after recovery: "
        f"{metrics['attacks_remaining_uncontained']}"
    )


    print(
        f"Post-recovery simulated containments: "
        f"{metrics['post_recovery_simulated_containments']}"
    )


    print(
        f"Defense reuse decisions: "
        f"{metrics['reused_defense_decisions']}"
    )


    print(
        f"New/known/repeated patterns: "
        f"{patterns['NEW']}/"
        f"{patterns['KNOWN']}/"
        f"{patterns['REPEATED']}"
    )


    print(
        f"Recovery audit records: "
        f"{stats['recovery_audit_events']}"
    )


    print(
        f"Verified recovery audit records: "
        f"{stats['verified_recoveries']}"
    )


    print(
        f"Threat Memory DB: "
        f"{stats}"
    )


    print(
        "\nWARNING:"
    )

    print(
        "Offline oracle-assisted recovery is an "
        "evaluation mechanism."
    )

    print(
        "It is NOT deployable autonomous recovery "
        "without observable live feedback."
    )


    print(
        f"\nSaved security_events.csv "
        f"and pipeline_summary.csv to {RUN_DIR}"
    )


    # ========================================================
    # DISPLAY FROZEN RL POLICY
    # ========================================================

    agent.display_policy()


    # ========================================================
    # CHART 1 — CUMULATIVE REWARD
    # ========================================================

    plt.figure(
        figsize=(10, 5)
    )


    plt.plot(

        reward_curve,

        linewidth=2
    )


    plt.title(
        "Frozen Q-Learning Policy: "
        "Offline Cumulative Reward"
    )


    plt.xlabel(
        "Flow step"
    )


    plt.ylabel(
        "Cumulative reward"
    )


    plt.grid(
        alpha=0.3
    )


    plt.tight_layout()


    plt.savefig(

        RUN_DIR / "rl_evaluation_curve.png",

        dpi=300,

        bbox_inches="tight"
    )


    plt.close()


    # ========================================================
    # CHART 2 — INITIAL RL ACTION DISTRIBUTION
    # ========================================================

    names = [
        "ALLOW",
        "ALERT",
        "BLOCK"
    ]


    risky = [

        metrics[
            "initial_missed_attacks"
        ],

        metrics[
            "initial_alert_only_attacks"
        ],

        metrics[
            "initial_false_blocks"
        ]
    ]


    safe = [

        actions[name]
        - risky[index]

        for index, name
        in enumerate(
            names
        )
    ]


    plt.figure(
        figsize=(9, 5)
    )


    plt.bar(

        names,

        safe,

        label="Other outcomes"
    )


    plt.bar(

        names,

        risky,

        bottom=safe,

        label="Risk / alerted attacks"
    )


    plt.title(
        "Initial RL Actions and Offline Risk"
    )


    plt.ylabel(
        "Flows"
    )


    plt.legend()


    plt.tight_layout()


    plt.savefig(

        RUN_DIR / "action_distribution_risk.png",

        dpi=300,

        bbox_inches="tight"
    )


    plt.close()


    # ========================================================
    # CHART 3 — BEFORE VS AFTER RECOVERY
    # ========================================================

    before = (
        metrics[
            "initial_simulated_containments"
        ]
    )


    after = (
        metrics[
            "post_recovery_simulated_containments"
        ]
    )


    plt.figure(
        figsize=(7, 5)
    )


    plt.bar(

        [
            "Initial Response",
            "After Recovery"
        ],

        [
            before,
            after
        ]
    )


    plt.title(
        "Offline Simulated Attack Containment: "
        "Before vs After Recovery"
    )


    plt.ylabel(
        "Contained Ground-Truth Attacks"
    )


    plt.ylim(
        0,
        max(
            metrics[
                "actual_attacks"
            ] * 1.10,
            1
        )
    )


    plt.tight_layout()


    plt.savefig(

        RUN_DIR / "self_healing_recovery_comparison.png",

        dpi=300,

        bbox_inches="tight"
    )


    plt.close()


    print(
        "Saved rl_evaluation_curve.png"
    )

    print(
        "Saved action_distribution_risk.png"
    )

    print(
        "Saved self_healing_recovery_comparison.png"
    )


    # ========================================================
    # STAGE 16 — CONTROLLED ENDPOINT HEALING DEMONSTRATION
    # ========================================================
    #
    # Real file quarantine / restoration / SHA-256 verification
    # inside runs/<RUN_ID>/endpoint_sim/. Triggered by this run's
    # own escalated recovery incidents. Not real Windows remediation.
    #
    # ========================================================

    endpoint_results = []

    if not args.skip_endpoint_demo:

        from endpoint_healing import run_demonstration

        print("\n" + "=" * 76)
        print("CONTROLLED ENDPOINT HEALING (SIMULATED ENDPOINTS)")
        print("=" * 76)

        endpoint_memory = ThreatMemory(
            THREAT_MEMORY_FILE
        )

        try:

            endpoint_results = run_demonstration(
                run_dir=RUN_DIR,
                run_id=RUN_ID,
                incidents=recovery_incidents,
                verifier=verifier,
                engine=healer,
                memory=endpoint_memory,
            )

        finally:

            endpoint_memory.close()

        for report in endpoint_results:

            print(
                f"{report['host_id']} {report['scenario']:20s} -> "
                f"{report['recovery_status']:20s} "
                f"integrity {report['integrity_summary']['files_passed']}/"
                f"{report['integrity_summary']['files_checked']} | "
                f"decision "
                f"{report['final_healing_decision']['healing_action']}"
            )

            for reason in report["failure_reasons"]:
                print("    failure:", reason)

    # ========================================================
    # STAGE 16B — CONTROLLED MULTI-STAGE APT CAMPAIGN (SIMULATED)
    # ========================================================

    apt_result = None

    if not args.skip_apt_demo:

        from apt_simulation import run_apt_campaign

        print("\n" + "=" * 76)
        print("CONTROLLED MULTI-STAGE APT CAMPAIGN (2 SIMULATED HOSTS)")
        print("=" * 76)

        apt_memory = ThreatMemory(THREAT_MEMORY_FILE)

        try:

            triggers = [
                inc for inc in recovery_incidents
                if healer.requires_endpoint_healing(inc)
            ]

            apt_result = run_apt_campaign(
                run_dir=RUN_DIR,
                run_id=RUN_ID,
                verifier=verifier,
                engine=healer,
                memory=apt_memory,
                trigger_incident=triggers[0] if triggers else None,
            )

        finally:

            apt_memory.close()

        for stage in apt_result["timeline"]:
            print(
                f"  {stage['seq']} {stage['tactic_id']} "
                f"{stage['tactic']:30s} {stage['host_id']}"
            )

        print(
            f"Correlated hosts: "
            f"{[(c['from_hosts'], c['to_host']) for c in apt_result['correlations']]}"
        )
        print(f"Campaign verdict: {apt_result['verdict']}")

    summary["apt_campaign_verdict"] = (
        apt_result["verdict"] if apt_result else "NOT_RUN"
    )

    summary["apt_campaign_stages"] = (
        len(apt_result["timeline"]) if apt_result else 0
    )

    summary["endpoint_scenarios_run"] = len(endpoint_results)

    summary["endpoints_healed_verified"] = sum(
        1 for r in endpoint_results if r["verified"]
    )

    summary["endpoints_healing_incomplete"] = sum(
        1 for r in endpoint_results if not r["verified"]
    )

    with open(
        RUN_DIR / "pipeline_summary.json",
        "w",
        encoding="utf-8"
    ) as handle:

        json.dump(summary, handle, indent=2, default=str)


    # ========================================================
    # STAGE 17 — RUN-DRIVEN DASHBOARD
    # ========================================================

    from dashboard_export import (
        build_run_data,
        export_dashboard,
        open_dashboard,
        validate_dashboard,
    )

    run_data = build_run_data(
        run_id=RUN_ID,
        run_dir=RUN_DIR,
        summary=summary,
        events_df=events_df,
        q_table=agent.q_table,
        endpoint_results=endpoint_results,
    )

    dashboard_path = export_dashboard(
        RUN_DIR,
        run_data
    )

    valid, detail = validate_dashboard(
        dashboard_path,
        RUN_ID
    )

    print(f"\nDashboard: {dashboard_path}")
    print(f"Dashboard validation: {'OK' if valid else 'FAILED'} ({detail})")

    if not valid:

        print("Dashboard NOT opened because validation failed.")

    elif args.no_browser:

        print("Browser launch skipped (--no-browser).")

    else:

        print(f"Opened in {open_dashboard(dashboard_path)}")

    return RUN_DIR


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()