# app/config.py

DATABASE_URL = "sqlite:///./app.db"

# Tryb pracy MFA:
# "always" | "adaptive"
AUTH_MODE = "adaptive"

# Progi ryzyka
RISK_LOW_THRESHOLD = 30
RISK_HIGH_THRESHOLD = 70
