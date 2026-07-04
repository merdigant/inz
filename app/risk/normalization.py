def clamp(value: float, min_value: float = 0.0, max_value: float = 100.0) -> float:
    return max(min_value, min(value, max_value))

def normalize(raw_score: int, max_raw_score: int) -> int:
    if max_raw_score <= 0:
        return 0
    normalized = (raw_score / max_raw_score) * 100
    return int(clamp(normalized))
