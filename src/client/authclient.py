"""Client for the WRAITH authority service: log in, cache the grant, refresh it.

Used by the ``wraith auth`` CLI. The HTTP client is injectable so tests can drive
it against an in-process authority app via httpx's ASGI transport.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx


class AuthError(Exception):
    """Raised when an authority call fails or required MFA input is missing."""


class AuthClient:
    """Thin client over the authority's auth endpoints."""

    def __init__(self, base_url: str, http_client: httpx.Client | None = None):
        self._owns = http_client is None
        self._http = http_client or httpx.Client(base_url=base_url.rstrip("/"), timeout=30.0)

    def close(self) -> None:
        if self._owns:
            self._http.close()

    def _post(self, path: str, body: dict) -> dict:
        resp = self._http.post(path, json=body)
        if resp.status_code != 200:
            raise AuthError(f"{path}: {resp.status_code} {resp.text}")
        result: dict = resp.json()
        return result

    def login(self, tenant: str, email: str, password: str, code: str | None = None) -> dict:
        """Log in and return the session (grant, refresh token, expiry).

        If the principal is MFA-required, the authority returns a challenge; this
        completes it with ``code`` (raising AuthError if no code was supplied).
        """
        result = self._post(
            "/v1/auth/login", {"tenant": tenant, "email": email, "password": password}
        )
        if result.get("mfa_required"):
            if not code:
                raise AuthError("MFA required: supply a TOTP code with --code")
            result = self._post(
                "/v1/auth/mfa/verify", {"challenge": result["challenge"], "code": code}
            )
        return result

    def refresh(self, refresh_token: str) -> dict:
        return self._post("/v1/auth/refresh", {"refresh_token": refresh_token})

    def me(self, grant: str) -> dict:
        resp = self._http.get("/v1/me", headers={"Authorization": f"Bearer {grant}"})
        if resp.status_code != 200:
            raise AuthError(f"/v1/me: {resp.status_code}")
        result: dict = resp.json()
        return result


def grant_expired(session: dict, at: datetime | None = None) -> bool:
    expires = session.get("expires_at")
    if not expires:
        return True
    try:
        moment = datetime.fromisoformat(expires)
    except ValueError:
        return True
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment <= (at or datetime.now(UTC))


def refreshed(client: AuthClient, session: dict) -> dict:
    """Return the session, refreshing the grant first if it has expired."""
    if not grant_expired(session):
        return session
    token = session.get("refresh_token")
    if not token:
        raise AuthError("session expired and no refresh token")
    return client.refresh(token)


def save_session(path: str | Path, session: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(session, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def load_session(path: str | Path) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
