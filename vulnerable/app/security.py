"""⚠️ VERSIÓN DELIBERADAMENTE VULNERABLE — SOLO LABORATORIO LOCAL ⚠️"""
import hashlib

import jwt

SECRET = "secret123"  # DEFECTO: secreto hardcodeado y débil
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # DEFECTO: MD5 sin sal


def verify_password(password: str, stored: str) -> bool:
    return hash_password(password) == stored


def create_token(user_id: int) -> str:
    return jwt.encode({"sub": str(user_id)}, SECRET, algorithm=ALGORITHM)  # DEFECTO: sin exp


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=[ALGORITHM])
