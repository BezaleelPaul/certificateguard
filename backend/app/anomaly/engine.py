from typing import List, Tuple
from app.anomaly.rules import ALL_ANOMALY_RULES, VerificationContext, AnomalyItem
from app.models import AnomalySeverity


class AnomalyEngine:
    """
    Evaluates rule-based anomalies against verification context.
    Produces structured list of findings and aggregate severity metrics.
    """

    def __init__(self, rules=None):
        self.rules = rules or ALL_ANOMALY_RULES

    def evaluate(self, context: VerificationContext) -> Tuple[List[AnomalyItem], AnomalySeverity]:
        detected_anomalies: List[AnomalyItem] = []
        highest_severity = AnomalySeverity.LOW

        severity_rank = {
            AnomalySeverity.LOW: 1,
            AnomalySeverity.MEDIUM: 2,
            AnomalySeverity.HIGH: 3,
            AnomalySeverity.CRITICAL: 4
        }

        current_max_rank = 0

        for rule in self.rules:
            try:
                anomaly = rule.evaluate(context)
                if anomaly:
                    detected_anomalies.append(anomaly)
                    rank = severity_rank.get(anomaly.severity, 1)
                    if rank > current_max_rank:
                        current_max_rank = rank
                        highest_severity = anomaly.severity
            except Exception as e:
                # Log rule failure without crashing engine
                print(f"Error executing anomaly rule {rule.rule_code}: {e}")

        return detected_anomalies, highest_severity


anomaly_engine = AnomalyEngine()
