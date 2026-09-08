from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password too long")

    return pwd_context.hash(password)



def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)
