from abc import ABC, abstractmethod
from datetime import timedelta

from app.risk.context import RiskContext


class RiskRule(ABC):
    @abstractmethod
    def evaluate(self, context: RiskContext) -> int:
        pass

class FailedAttemptsRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        failed = [a for a in context.login_history if not a.success]
        return 40 if len(failed) >= 3 else 0

class LastAttemptFailedRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if context.login_history and not context.login_history[0].success:
            return 30
        return 0

class NewIPRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if not context.ip_address:
            return 0

        known_ips = {
            a.ip_address
            for a in context.login_history
            if a.ip_address
        }

        return 30 if context.ip_address not in known_ips else 0

class NewUserAgentRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if not context.user_agent:
            return 0

        known_agents = {
            a.user_agent
            for a in context.login_history
            if a.user_agent
        }

        return 20 if context.user_agent not in known_agents else 0

class UnusualHourRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        hour = context.login_time.hour
        if hour < 6 or hour >= 23:
            return 15
        return 0


class UnusualLoginPatternRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        hours = [
            a.timestamp.hour
            for a in context.login_history
            if a.success
        ]

        if not hours:
            return 0

        avg_hour = sum(hours) / len(hours)
        diff = abs(context.login_time.hour - avg_hour)

        return 20 if diff >= 6 else 0

class NewCountryRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if not context.country:
            return 0

        known = {
            a.country
            for a in context.login_history
            if a.country
        }

        return 40 if context.country not in known else 0

class RiskyASNRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if not context.asn_org:
            return 0

        risky_keywords = ["hosting", "cloud", "vpn", "server"]

        name = context.asn_org.lower()

        if any(k in name for k in risky_keywords):
            return 30

        return 0

class ImpossibleTravelRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if not context.country:
            return 0

        for a in context.login_history:
            if a.country and a.country != context.country:
                delta = context.login_time - a.timestamp
                if delta < timedelta(hours=2):
                    return 50
        return 0

class RapidAttemptsRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        history = context.login_history
        if len(history) < 3:
            return 0

        t0 = history[0].timestamp
        t2 = history[2].timestamp

        if t0 - t2 < timedelta(seconds=60):
            return 30
        return 0

class PositiveLoginHistoryRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        successes = [
            a for a in context.login_history
            if a.success
        ]

        if len(successes) >= 10:
            return -20
        return 0

class ChronicRiskRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        risky = [
            r for r in context.risk_history
            if r.decision == "MFA_REQUIRED"
        ]

        if len(risky) >= 3:
            return 30
        return 0

class ConfidenceDecayRule(RiskRule):
    def evaluate(self, context: RiskContext) -> int:
        if not context.risk_history:
            return 0

        last = context.risk_history[0]
        delta = context.login_time - last.timestamp

        if delta > timedelta(days=7):
            return -15
        return 0
