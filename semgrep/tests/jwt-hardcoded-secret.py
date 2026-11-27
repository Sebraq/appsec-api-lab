import os
import jwt

SECRET = "secret123"


def bad_literal(payload):
    # ruleid: appsec-lab.jwt-hardcoded-secret
    return jwt.encode(payload, "literal-key", algorithm="HS256")


def bad_constant(payload):
    # ruleid: appsec-lab.jwt-hardcoded-secret
    return jwt.encode(payload, SECRET, algorithm="HS256")


def bad_decode(token):
    # ruleid: appsec-lab.jwt-hardcoded-secret
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def good_encode(payload):
    key = os.environ["APP_SECRET_KEY"]
    # ok: appsec-lab.jwt-hardcoded-secret
    return jwt.encode(payload, key, algorithm="HS256")
