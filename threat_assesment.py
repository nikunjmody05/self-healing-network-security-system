class ThreatAssessment:

    def __init__(self):
        self.severity_levels = {
            "LOW": (0, 24),
            "MEDIUM": (25, 49),
            "HIGH": (50, 74),
            "CRITICAL": (75, 100)
        }

    def calculate_score(self, prediction, confidence):
        """
        Convert ML prediction + confidence into a threat score.

        prediction:
            0 = BENIGN
            1 = ATTACK

        confidence:
            ML confidence between 0 and 1
        """

        confidence = max(0.0, min(1.0, confidence))

        if prediction == 1:
            # High confidence attack = high threat
            score = confidence * 100
        else:
            # High confidence benign = low threat
            score = (1 - confidence) * 100

        return round(score, 2)

    def get_severity(self, score):

        if score <= 24:
            return "LOW"

        elif score <= 49:
            return "MEDIUM"

        elif score <= 74:
            return "HIGH"

        else:
            return "CRITICAL"

    def assess(self, prediction, confidence):

        score = self.calculate_score(
            prediction,
            confidence
        )

        severity = self.get_severity(score)

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "threat_score": score,
            "severity": severity
        }