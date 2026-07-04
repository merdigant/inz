MFA_POLICIES = {
    "LOW_FRICTION": {
        "mfa_threshold": 70,
        "block_threshold": 90
    },
    "STANDARD": {
        "mfa_threshold": 60,
        "block_threshold": 80
    },
    "STRICT": {
        "mfa_threshold": 30,
        "block_threshold": 70
    }
}

def decide_mfa(score: int, policy_name: str) -> str:
    policy = MFA_POLICIES.get(policy_name)

    if not policy:
        raise ValueError("Unknown MFA policy")

    if score >= policy["block_threshold"]:
        return "BLOCK"

    if score >= policy["mfa_threshold"]:
        return "MFA_REQUIRED"

    return "ALLOW"
