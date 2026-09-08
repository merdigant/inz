from app.risk.normalization import normalize


def test_normalize_zero():
    assert normalize(0) == 0


def test_normalize_mid():
    assert normalize(49) == 49


def test_normalize_max():
    assert normalize(335) == 100


def test_normalize_overflow():
    assert normalize(500) == 100


def test_normalize_negative():
    assert normalize(-50) == 0
