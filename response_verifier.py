# ============================================================
# RESPONSE VERIFIER
# ============================================================


class ResponseVerifier:

    def __init__(self):

        print("Response Verifier Ready.")


    # ========================================================
    # VERIFY RESPONSE
    # ========================================================

    def verify(
        self,
        action,
        response,
        prediction,
        severity,
        verification_mode="SIMULATED",
        observed_outcome=None,
        true_label=None
    ):

        action = str(action).upper()

        verification_mode = str(
            verification_mode
        ).upper()


        # ====================================================
        # SIMULATED OFFLINE VERIFICATION
        # ====================================================
        #
        # Used during CIC-IDS2017 replay.
        #
        # IMPORTANT:
        #
        # true_label is NEVER used to select the RL action.
        #
        # It is supplied only AFTER the defensive action has
        # already been selected and executed.
        #
        # This allows us to evaluate the simulated security
        # outcome without leaking ground truth into the policy.
        #
        # ====================================================

        if verification_mode == "SIMULATED":

            return self._verify_simulated(
                action=action,
                response=response,
                prediction=prediction,
                severity=severity,
                true_label=true_label
            )


        # ====================================================
        # LIVE VERIFICATION
        # ====================================================

        elif verification_mode == "LIVE":

            return self._verify_live(
                action=action,
                observed_outcome=observed_outcome
            )


        # ====================================================
        # ENDPOINT INTEGRITY VERIFICATION
        # ====================================================
        #
        # Evidence comes from re-hashing the simulated endpoint
        # (endpoint_healing.py). It does NOT use ground truth.
        #
        # ====================================================

        elif verification_mode == "ENDPOINT_INTEGRITY":

            return self._verify_endpoint(
                observed_outcome=observed_outcome
            )


        # ====================================================
        # UNKNOWN VERIFICATION MODE
        # ====================================================

        return {

            "verified":
                False,

            "verification_status":
                "UNKNOWN",

            "verification_mode":
                verification_mode,

            "verification_type":
                "UNKNOWN",

            "containment_success":
                False,

            "reason":
                "Unsupported verification mode",

            "recovery_required":
                False
        }


    # ========================================================
    # SIMULATED VERIFICATION
    # ========================================================

    def _verify_simulated(
        self,
        action,
        response,
        prediction,
        severity,
        true_label=None
    ):

        # ====================================================
        # MODE 1 — NO GROUND TRUTH PROVIDED
        # ====================================================
        #
        # This preserves the original response-execution
        # verification behaviour.
        #
        # It answers:
        #
        # "Did the Response Engine execute the response that
        # was expected from the ML/RL decision?"
        #
        # It does NOT claim real attack containment.
        #
        # ====================================================

        if true_label is None:

            # ------------------------------------------------
            # BLOCK
            # ------------------------------------------------

            if action == "BLOCK":

                success = (
                    prediction == 1
                    and response == "TRAFFIC BLOCKED"
                )


            # ------------------------------------------------
            # ALERT
            # ------------------------------------------------

            elif action == "ALERT":

                success = (
                    response
                    == "SECURITY ALERT GENERATED"
                )


            # ------------------------------------------------
            # ALLOW
            # ------------------------------------------------

            elif action == "ALLOW":

                success = (
                    prediction == 0
                    and response == "TRAFFIC ALLOWED"
                )


            # ------------------------------------------------
            # UNKNOWN ACTION
            # ------------------------------------------------

            else:

                return {

                    "verified":
                        False,

                    "verification_status":
                        "UNKNOWN",

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "RESPONSE_EXECUTION",

                    "containment_success":
                        False,

                    "reason":
                        (
                            f"Unknown response action: "
                            f"{action}"
                        ),

                    "recovery_required":
                        True
                }


            return {

                "verified":
                    success,

                "verification_status":
                    (
                        "SUCCESS"
                        if success
                        else "FAILED"
                    ),

                "verification_mode":
                    "SIMULATED",

                "verification_type":
                    "RESPONSE_EXECUTION",

                # Execution verification is NOT the same
                # as verified threat containment.
                "containment_success":
                    False,

                "reason":
                    (
                        "Intended response executed successfully"
                        if success
                        else
                        "Intended response execution failed"
                    ),

                "recovery_required":
                    not success
            }


        # ====================================================
        # MODE 2 — GROUND TRUTH AVAILABLE
        # ====================================================
        #
        # Ground truth is used ONLY for offline evaluation
        # after the action has already been selected.
        #
        # ====================================================

        true_label = int(
            true_label
        )


        # ====================================================
        # GROUND-TRUTH ATTACK
        # ====================================================

        if true_label == 1:

            # ------------------------------------------------
            # ATTACK + BLOCK
            # ------------------------------------------------

            if action == "BLOCK":

                success = (
                    response == "TRAFFIC BLOCKED"
                )


                return {

                    "verified":
                        success,

                    "verification_status":
                        (
                            "SUCCESS"
                            if success
                            else "FAILED"
                        ),

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "SIMULATED_CONTAINMENT",

                    "containment_success":
                        success,

                    "reason":
                        (
                            "Ground-truth attack received "
                            "the intended simulated BLOCK "
                            "response"
                            if success
                            else
                            "Ground-truth attack was not "
                            "successfully blocked"
                        ),

                    "recovery_required":
                        not success
                }


            # ------------------------------------------------
            # ATTACK + ALERT
            # ------------------------------------------------

            elif action == "ALERT":

                alert_generated = (
                    response
                    == "SECURITY ALERT GENERATED"
                )


                return {

                    # The alert itself may have been
                    # successfully generated.
                    "verified":
                        alert_generated,

                    "verification_status":
                        (
                            "SUCCESS"
                            if alert_generated
                            else "FAILED"
                        ),

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "THREAT_ALERT",

                    # ALERT provides visibility.
                    # It does not contain the attack.
                    "containment_success":
                        False,

                    "reason":
                        (
                            "Ground-truth attack generated "
                            "a security alert but remains "
                            "uncontained"
                            if alert_generated
                            else
                            "Ground-truth attack failed to "
                            "generate the expected alert"
                        ),

                    # Even if the alert was generated,
                    # containment is still required.
                    "recovery_required":
                        True
                }


            # ------------------------------------------------
            # ATTACK + ALLOW
            # ------------------------------------------------

            elif action == "ALLOW":

                return {

                    "verified":
                        False,

                    "verification_status":
                        "FAILED",

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "SIMULATED_CONTAINMENT",

                    "containment_success":
                        False,

                    "reason":
                        (
                            "Ground-truth attack was "
                            "incorrectly allowed"
                        ),

                    "recovery_required":
                        True
                }


        # ====================================================
        # GROUND-TRUTH BENIGN TRAFFIC
        # ====================================================

        elif true_label == 0:

            # ------------------------------------------------
            # BENIGN + ALLOW
            # ------------------------------------------------

            if action == "ALLOW":

                success = (
                    response == "TRAFFIC ALLOWED"
                )


                return {

                    "verified":
                        success,

                    "verification_status":
                        (
                            "SUCCESS"
                            if success
                            else "FAILED"
                        ),

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "BENIGN_RESPONSE",

                    # Benign traffic is not a containment.
                    "containment_success":
                        False,

                    "reason":
                        (
                            "Ground-truth benign traffic "
                            "was correctly allowed"
                            if success
                            else
                            "Benign traffic ALLOW "
                            "response failed"
                        ),

                    "recovery_required":
                        False
                }


            # ------------------------------------------------
            # BENIGN + ALERT
            # ------------------------------------------------

            elif action == "ALERT":

                return {

                    "verified":
                        False,

                    "verification_status":
                        "UNNECESSARY_RESPONSE",

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "FALSE_POSITIVE_RESPONSE",

                    "containment_success":
                        False,

                    "reason":
                        (
                            "Ground-truth benign traffic "
                            "was unnecessarily alerted"
                        ),

                    "recovery_required":
                        False
                }


            # ------------------------------------------------
            # BENIGN + BLOCK
            # ------------------------------------------------

            elif action == "BLOCK":

                return {

                    "verified":
                        False,

                    "verification_status":
                        "FALSE_BLOCK",

                    "verification_mode":
                        "SIMULATED",

                    "verification_type":
                        "FALSE_POSITIVE_RESPONSE",

                    "containment_success":
                        False,

                    "reason":
                        (
                            "Ground-truth benign traffic "
                            "was incorrectly blocked"
                        ),

                    "recovery_required":
                        False
                }


        # ====================================================
        # FALLBACK
        # ====================================================

        return {

            "verified":
                False,

            "verification_status":
                "UNKNOWN",

            "verification_mode":
                "SIMULATED",

            "verification_type":
                "UNKNOWN",

            "containment_success":
                False,

            "reason":
                (
                    "Unable to evaluate simulated "
                    "response outcome"
                ),

            "recovery_required":
                True
        }


    # ========================================================
    # LIVE VERIFICATION
    # ========================================================

    def _verify_live(
        self,
        action,
        observed_outcome
    ):

        # ====================================================
        # PHASE 5 LIVE VERIFICATION
        # ====================================================
        #
        # Later this will evaluate observable network evidence:
        #
        # - Was the firewall/block rule accepted?
        # - Did traffic from the source stop?
        # - Did the malicious flow recur?
        # - Is the source still communicating?
        # - Did isolation actually take effect?
        #
        # Until such evidence exists, LIVE mode must NEVER
        # automatically claim successful containment.
        #
        # ====================================================


        # ----------------------------------------------------
        # NO LIVE EVIDENCE YET
        # ----------------------------------------------------

        if observed_outcome is None:

            return {

                "verified":
                    False,

                "verification_status":
                    "PENDING",

                "verification_mode":
                    "LIVE",

                "verification_type":
                    "LIVE_TELEMETRY",

                "containment_success":
                    False,

                "reason":
                    (
                        "No live verification evidence "
                        "available"
                    ),

                "recovery_required":
                    False
            }


        # ----------------------------------------------------
        # READ OBSERVED OUTCOME
        # ----------------------------------------------------

        success = bool(
            observed_outcome.get(
                "success",
                False
            )
        )


        # ----------------------------------------------------
        # LIVE SUCCESS
        # ----------------------------------------------------

        if success:

            return {

                "verified":
                    True,

                "verification_status":
                    "SUCCESS",

                "verification_mode":
                    "LIVE",

                "verification_type":
                    "LIVE_TELEMETRY",

                "containment_success":
                    True,

                "reason":
                    observed_outcome.get(
                        "reason",
                        (
                            "Live response verified "
                            "successfully"
                        )
                    ),

                "recovery_required":
                    False
            }


        # ----------------------------------------------------
        # LIVE FAILURE
        # ----------------------------------------------------

        return {

            "verified":
                False,

            "verification_status":
                "FAILED",

            "verification_mode":
                "LIVE",

            "verification_type":
                "LIVE_TELEMETRY",

            "containment_success":
                False,

            "reason":
                observed_outcome.get(
                    "reason",
                    (
                        "Live response verification "
                        "failed"
                    )
                ),

            "recovery_required":
                True
        }


    # ========================================================
    # ENDPOINT INTEGRITY VERIFICATION
    # ========================================================

    def _verify_endpoint(
        self,
        observed_outcome
    ):

        # observed_outcome is an endpoint healing report.
        # Success requires every SHA-256 check to pass AND no
        # unauthorized artefacts remaining.

        if not observed_outcome:

            return {
                "verified": False,
                "verification_status": "PENDING",
                "verification_mode": "ENDPOINT_INTEGRITY",
                "verification_type": "ENDPOINT_SHA256",
                "containment_success": False,
                "reason": "No endpoint integrity evidence available",
                "recovery_required": False
            }

        checks = observed_outcome.get(
            "integrity_checks",
            []
        )

        failed = [
            c["path"] for c in checks
            if not c.get("passed")
        ]

        leftovers = observed_outcome.get(
            "unauthorized_files_remaining",
            []
        )

        success = (
            bool(checks)
            and not failed
            and not leftovers
        )

        return {
            "verified": success,
            "verification_status": (
                "SUCCESS" if success else "FAILED"
            ),
            "verification_mode": "ENDPOINT_INTEGRITY",
            "verification_type": "ENDPOINT_SHA256",
            "containment_success": success,
            "reason": (
                f"All {len(checks)} files match the trusted "
                f"baseline and no unauthorized artefacts remain"
                if success
                else
                f"Integrity failed for {failed or 'no files checked'}; "
                f"unauthorized remaining: {leftovers}"
            ),
            "recovery_required": not success
        }


# ============================================================
# MODULE READY
# ============================================================

print(
    "Response Verifier Module Loaded."
)