import secrets
import hashlib
import jwt
import os

from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(user_id: int):

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iss": "authentication-system",
        "aud": "authentication-api",
        "type": "access"
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def verify_access_token(token: str):

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
        issuer="authentication-system",
        audience="authentication-api",
        options={
            "require": ["sub", "exp", "iss", "aud", "type"]
        }
    )

    if payload["type"] != "access":
        raise jwt.InvalidTokenError("Invalid token type")

    return int(payload["sub"])

REFRESH_TOKEN_EXPIRE_DAYS = 7


def generate_refresh_token():
    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str):
    return hashlib.sha256(token.encode()).hexdigest()
