"""TOTP MFA helpers: secret encryption at rest and short-lived login challenges.

TOTP secrets are stored Fernet-encrypted under the service MFA key. The login
challenge issued after the password step (before the TOTP step) is a Fernet token
with a short TTL, so it is tamper-proof and self-expiring. The same MFA key
protects both.
"""

from __future__ import annotations

import json
import uuid

import pyotp
from cryptography.fernet import Fernet, InvalidToken

CHALLENGE_TTL_SECONDS = 300
_ISSUER = "WRAITH"


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=_ISSUER)


def verify_code(secret: str, code: str) -> bool:
    # valid_window=1 tolerates a one-step clock skew between client and server.
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


def encrypt_secret(key: bytes, secret: str) -> str:
    return Fernet(key).encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(key: bytes, token: str) -> str:
    return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")


def make_challenge(key: bytes, principal_id: str, tenant_id: str) -> str:
    # The jti makes the challenge single-use: it is recorded when redeemed at
    # /v1/auth/mfa/verify and a second presentation of the same challenge is
    # refused, so a captured challenge cannot mint more than one session.
    payload = json.dumps(
        {"principal_id": principal_id, "tenant_id": tenant_id, "jti": uuid.uuid4().hex}
    )
    return Fernet(key).encrypt(payload.encode("utf-8")).decode("ascii")


def read_challenge(key: bytes, token: str) -> dict | None:
    try:
        raw = Fernet(key).decrypt(token.encode("ascii"), ttl=CHALLENGE_TTL_SECONDS)
    except InvalidToken:
        return None
    return json.loads(raw)
