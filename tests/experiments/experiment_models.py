from dataclasses import dataclass, field
from typing import List

from app.models import LoginAttempt
from app.risk.context import RiskContext


@dataclass
class UserProfile:
    username: str
    profile_type: str
    home_country: str
    home_ip: str
    home_asn: int
    home_asn_org: str
    home_user_agent: str
    typical_hours: tuple[int, int]
    history: List[LoginAttempt] = field(default_factory=list)


@dataclass
class Scenario:
    profile: UserProfile
    name: str
    context: RiskContext


@dataclass
class ExperimentResult:
    username: str
    profile_type: str
    scenario: str
    permission_level: str
    expected: str | None
    score: int
    raw_score: int
    decision: str
    execution_time_ms: float