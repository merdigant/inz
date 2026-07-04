from app.risk.context import RiskContext
from app.risk.rules import RiskRule


class RiskEngine:
    def __init__(self, rules: list[RiskRule]):
        self.rules = rules

    def calculate(self, context: RiskContext) -> int:
        return sum(rule.evaluate(context) for rule in self.rules)

    def calculate_with_trace(self, context):
        total = 0
        trace = []

        for rule in self.rules:
            score = rule.evaluate(context)
            if score != 0:
                trace.append({
                    "rule": rule.__class__.__name__,
                    "score": score
                })
            total += score

        return total, trace
