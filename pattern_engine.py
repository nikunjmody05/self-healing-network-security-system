import hashlib
import json


class PatternEngine:

    def __init__(self, threat_memory):

        self.memory = threat_memory

        print("Pattern Engine V2 Ready.")


    # ========================================================
    # GENERIC CATEGORY FUNCTION
    # ========================================================

    def _categorize(
        self,
        value,
        p25,
        median,
        p75
    ):

        try:
            value = float(value)

        except (TypeError, ValueError):
            return "UNKNOWN"


        if value <= p25:
            return "LOW"

        elif value <= median:
            return "MODERATE"

        elif value <= p75:
            return "HIGH"

        else:
            return "EXTREME"


    # ========================================================
    # BUILD BEHAVIOR PROFILE
    # ========================================================

    def build_behavior_profile(
        self,
        prediction,
        confidence,
        threat_score,
        severity,
        features=None
    ):

        if features is None:
            features = {}


        profile = {

            "prediction":
                int(prediction),

            "confidence_bucket":
                min(
                    int(float(confidence) * 10),
                    9
                ),

            "severity":
                str(severity)
        }


        # ====================================================
        # ATTACK-DISTRIBUTION QUARTILE BOUNDARIES
        #
        # Derived from our 50,000-row CIC-IDS2017 analysis.
        # ====================================================

        rules = {

            "Flow Duration": (
                17405.5,
                1167315.0,
                10702668.0
            ),

            "Flow Packets/s": (
                0.3638,
                6.1316,
                322.8447
            ),

            "Flow Bytes/s": (
                0.0,
                687.8478,
                36891.3943
            ),

            "Fwd Packet Length Mean": (
                0.0,
                8.6667,
                108.6667
            ),

            "Bwd Packet Length Mean": (
                0.0,
                32.25,
                241.0
            ),

            "Flow IAT Mean": (
                3778.8333,
                190698.25,
                3539143.4375
            ),

            "Flow IAT Std": (
                20.7567,
                16878.8887,
                646764.4688
            ),

            "Packet Length Variance": (
                0.0,
                13318.6963,
                115523.4297
            )
        }


        for feature_name, thresholds in rules.items():

            if feature_name in features:

                profile[feature_name] = (
                    self._categorize(
                        features[feature_name],
                        thresholds[0],
                        thresholds[1],
                        thresholds[2]
                    )
                )


        return profile


    # ========================================================
    # BUILD PATTERN SIGNATURE
    # ========================================================

    def build_pattern_signature(
        self,
        behavior_profile
    ):

        # ----------------------------------------------------
        # Only the core behavioral dimensions determine
        # pattern identity.
        #
        # Explanation-only characteristics remain available
        # in behavior_profile.
        # ----------------------------------------------------

        identity_features = [

            "prediction",

            "severity",

            "Flow Duration",

            "Flow Packets/s",

            "Flow Bytes/s",

            "Fwd Packet Length Mean",

            "Bwd Packet Length Mean"
        ]


        signature = {}


        for feature in identity_features:

            if feature in behavior_profile:

                signature[feature] = (
                    behavior_profile[feature]
                )


        return signature


    # ========================================================
    # GENERATE FINGERPRINT
    # ========================================================

    def generate_fingerprint(
        self,
        pattern_signature
    ):

        serialized = json.dumps(

            pattern_signature,

            sort_keys=True,

            separators=(",", ":")
        )


        return hashlib.sha256(

            serialized.encode("utf-8")

        ).hexdigest()


    # ========================================================
    # PATTERN ID
    # ========================================================

    def generate_pattern_id(
        self,
        fingerprint
    ):

        return (
            "PAT-"
            + fingerprint[:12].upper()
        )


    # ========================================================
    # ANALYZE
    # ========================================================

    def analyze(
        self,
        prediction,
        confidence,
        threat_score,
        severity,
        features=None
    ):

        behavior_profile = (
            self.build_behavior_profile(

                prediction=prediction,

                confidence=confidence,

                threat_score=threat_score,

                severity=severity,

                features=features
            )
        )


        pattern_signature = (
            self.build_pattern_signature(
                behavior_profile
            )
        )


        fingerprint = (
            self.generate_fingerprint(
                pattern_signature
            )
        )


        existing_pattern = (
            self.memory
            .get_pattern_by_fingerprint(
                fingerprint
            )
        )


        # ====================================================
        # NEW
        # ====================================================

        if existing_pattern is None:

            pattern_id = (
                self.generate_pattern_id(
                    fingerprint
                )
            )


            return {

                "pattern_status":
                    "NEW",

                "pattern_id":
                    pattern_id,

                "fingerprint":
                    fingerprint,

                "occurrence_count":
                    0,

                "previous_action":
                    None,

                "previous_response":
                    None,

                "previous_successful_containments":
                    0,

                "behavior_profile":
                    behavior_profile,

                "pattern_signature":
                    pattern_signature
            }


        # ====================================================
        # KNOWN / REPEATED
        # ====================================================

        occurrence_count = (
            existing_pattern[
                "occurrence_count"
            ]
        )


        if occurrence_count <= 1:

            status = "KNOWN"

        else:

            status = "REPEATED"


        return {

            "pattern_status":
                status,

            "pattern_id":
                existing_pattern[
                    "pattern_id"
                ],

            "fingerprint":
                fingerprint,

            "occurrence_count":
                occurrence_count,

            "previous_action":
                existing_pattern[
                    "last_action"
                ],

            "previous_response":
                existing_pattern[
                    "last_response"
                ],

            "previous_successful_containments":
                existing_pattern[
                    "successful_containments"
                ],

            "behavior_profile":
                behavior_profile,

            "pattern_signature":
                pattern_signature
        }