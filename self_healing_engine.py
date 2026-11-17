class SelfHealingEngine:

    def __init__(self):

        print("Self-Healing Engine Ready.")


    # ========================================================
    # HEAL
    # ========================================================

    def heal(
        self,
        prediction,
        severity,
        current_action,
        verification_result,
        pattern_status="NEW",
        occurrence_count=0,
        previous_action=None,
        previous_successful_containments=0
    ):

        verified = verification_result.get(
            "verified",
            False
        )

        verification_status = verification_result.get(
            "verification_status",
            "UNKNOWN"
        )

        recovery_required = verification_result.get(
            "recovery_required",
            False
        )


        # ====================================================
        # CASE 1 — RESPONSE VERIFIED SUCCESSFULLY
        # ====================================================

        if verified and not recovery_required:

            # ------------------------------------------------
            # REPEATED THREAT + PREVIOUS SUCCESS
            # ------------------------------------------------

            if (
                prediction == 1
                and pattern_status == "REPEATED"
                and previous_successful_containments > 0
            ):

                return {

                    "healing_status":
                        "STABLE",

                    "healing_action":
                        "REUSE_DEFENSE",

                    "recommended_action":
                        current_action,

                    "policy_update":
                        "REINFORCE_EXISTING_RESPONSE",

                    "reason":
                        (
                            "Repeated threat matched a pattern "
                            "with previously successful containment"
                        ),

                    "escalation_required":
                        False
                }


            # ------------------------------------------------
            # NORMAL VERIFIED SUCCESS
            # ------------------------------------------------

            return {

                "healing_status":
                    "STABLE",

                "healing_action":
                    "MAINTAIN",

                "recommended_action":
                    current_action,

                "policy_update":
                    "RECORD_SUCCESS",

                "reason":
                    (
                        "Current response was verified "
                        "successfully"
                    ),

                "escalation_required":
                    False
            }


        # ====================================================
        # CASE 2 — LIVE VERIFICATION STILL PENDING
        # ====================================================

        if verification_status == "PENDING":

            return {

                "healing_status":
                    "MONITORING",

                "healing_action":
                    "WAIT_FOR_VERIFICATION",

                "recommended_action":
                    current_action,

                "policy_update":
                    "NONE",

                "reason":
                    (
                        "Response outcome has not yet "
                        "been verified"
                    ),

                "escalation_required":
                    False
            }


        # ====================================================
        # CASE 3 — NO RECOVERY REQUIRED
        # ====================================================

        if not recovery_required:

            return {

                "healing_status":
                    "MONITORING",

                "healing_action":
                    "CONTINUE_MONITORING",

                "recommended_action":
                    current_action,

                "policy_update":
                    "NONE",

                "reason":
                    (
                        "No immediate recovery action "
                        "is required"
                    ),

                "escalation_required":
                    False
            }


        # ====================================================
        # CASE 4 — THREAT WAS ALLOWED
        # ====================================================

        if (
            prediction == 1
            and current_action == "ALLOW"
        ):

            # Critical/high threats should move directly
            # to containment.

            if severity in [
                "HIGH",
                "CRITICAL"
            ]:

                return {

                    "healing_status":
                        "RECOVERY_REQUIRED",

                    "healing_action":
                        "ESCALATE",

                    "recommended_action":
                        "BLOCK",

                    "policy_update":
                        "ESCALATE_RESPONSE",

                    "reason":
                        (
                            "Threat was incorrectly allowed; "
                            "high-risk traffic requires containment"
                        ),

                    "escalation_required":
                        True
                }


            # Lower-risk threat:
            # first escalate to SOC visibility.

            return {

                "healing_status":
                    "RECOVERY_REQUIRED",

                "healing_action":
                    "ESCALATE",

                "recommended_action":
                    "ALERT",

                "policy_update":
                    "ESCALATE_RESPONSE",

                "reason":
                    (
                        "Threat was incorrectly allowed; "
                        "escalating to security alert"
                    ),

                "escalation_required":
                    True
            }


        # ====================================================
        # CASE 5 — ALERT FAILED / INSUFFICIENT
        # ====================================================

        if (
            prediction == 1
            and current_action == "ALERT"
        ):

            return {

                "healing_status":
                    "RECOVERY_REQUIRED",

                "healing_action":
                    "ESCALATE",

                "recommended_action":
                    "BLOCK",

                "policy_update":
                    "ESCALATE_RESPONSE",

                "reason":
                    (
                        "Alert response was insufficient; "
                        "escalating to containment"
                    ),

                "escalation_required":
                    True
            }


        # ====================================================
        # CASE 6 — BLOCK FAILED
        # ====================================================

        if (
            prediction == 1
            and current_action == "BLOCK"
        ):

            return {

                "healing_status":
                    "RECOVERY_REQUIRED",

                "healing_action":
                    "ISOLATE",

                "recommended_action":
                    "ISOLATE",

                "policy_update":
                    "MARK_BLOCK_FAILURE",

                "reason":
                    (
                        "Containment failed; network isolation "
                        "and SOC escalation are required"
                    ),

                "escalation_required":
                    True
            }


        # ====================================================
        # FALLBACK
        # ====================================================

        return {

            "healing_status":
                "REVIEW_REQUIRED",

            "healing_action":
                "SOC_REVIEW",

            "recommended_action":
                "ALERT",

            "policy_update":
                "MANUAL_REVIEW",

            "reason":
                (
                    "Response outcome requires "
                    "security analyst review"
                ),

            "escalation_required":
                True
        }


    # ========================================================
    # ENDPOINT HEALING INTEGRATION
    # ========================================================

    def requires_endpoint_healing(
        self,
        healing_result
    ):
        """
        An escalation or failed containment means the targeted endpoint
        must be checked and restored (controlled simulation).
        """

        return healing_result.get(
            "healing_action"
        ) in {
            "ESCALATE",
            "ISOLATE"
        }


    def assess_endpoint_healing(
        self,
        endpoint_verification
    ):
        """
        Decide the final self-healing outcome from ENDPOINT_INTEGRITY
        verification evidence (SHA-256 re-check), not from a flag.
        """

        if endpoint_verification.get("verified"):

            return {
                "healing_status": "RECOVERED",
                "healing_action": "ENDPOINT_RESTORED",
                "recommended_action": "MAINTAIN",
                "policy_update": "RECORD_SUCCESS",
                "reason": endpoint_verification.get("reason"),
                "escalation_required": False
            }

        if endpoint_verification.get(
            "verification_status"
        ) == "PENDING":

            return {
                "healing_status": "MONITORING",
                "healing_action": "WAIT_FOR_VERIFICATION",
                "recommended_action": "ALERT",
                "policy_update": "NONE",
                "reason": endpoint_verification.get("reason"),
                "escalation_required": False
            }

        return {
            "healing_status": "RECOVERY_INCOMPLETE",
            "healing_action": "SOC_REVIEW",
            "recommended_action": "ISOLATE",
            "policy_update": "MARK_HEALING_FAILURE",
            "reason": (
                "Endpoint could not be verified as restored: "
                + str(endpoint_verification.get("reason"))
            ),
            "escalation_required": True
        }


print("Self-Healing Engine Module Loaded.")