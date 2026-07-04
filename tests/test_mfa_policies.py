from app.risk.policies import decide_mfa


def test_low_friction_policy():
    assert decide_mfa(69, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(80, "LOW_FRICTION") == "MFA_REQUIRED"
    assert decide_mfa(90, "LOW_FRICTION") == "BLOCK"


def test_standard_policy():
    assert decide_mfa(49, "STANDARD") == "ALLOW"
    assert decide_mfa(60, "STANDARD") == "MFA_REQUIRED"
    assert decide_mfa(80, "STANDARD") == "BLOCK"


def test_strict_policy():
    assert decide_mfa(29, "STRICT") == "ALLOW"
    assert decide_mfa(30, "STRICT") == "MFA_REQUIRED"
    assert decide_mfa(70, "STRICT") == "BLOCK"
