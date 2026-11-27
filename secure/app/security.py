"""Hash de contraseñas y manejo de tokens JWT (versión corregida)."""
import hashlib
import hmac
import os
import secrets
import time

import jwt

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 15 * 60


def _secret() -> str:
    key = os.environ.get("APP_SECRET_KEY", "")
    if len(key) < 32:
        raise RuntimeError("APP_SECRET_KEY no definida o menor a 32 caracteres")
    return key


def check_config() -> None:
    _secret()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(dk.hex(), dk_hex)


def create_token(user_id: int) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(
        token, _secret(), algorithms=[ALGORITHM], options={"require": ["exp", "sub"]}
    )
