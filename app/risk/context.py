from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from app.models import LoginAttempt, RiskAssessment


@dataclass
class RiskContext:
    username: str
    login_history: List[LoginAttempt]
    login_time: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    country: Optional[str]
    asn: Optional[int]
    risk_history: List[RiskAssessment]
    asn_org: Optional[str] = None
