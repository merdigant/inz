def clamp(value: float, min_value: float = 0.0, max_value: float = 100.0) -> float:
    return max(min_value, min(value, max_value))

def normalize(raw_score: int) -> int:
    return max(0, min(100, round(raw_score / 100 * 100)))