"""Client for the WRAITH Runner service: engagements and scans.

Carries the CapabilityGrant obtained from the authority (see AuthClient) as a bearer
token. The HTTP client is injectable so tests drive it against an in-process Runner
app.
"""

from __future__ import annotations

import time

import httpx


class RunnerError(Exception):
    """Raised when a Runner call fails."""


class RunnerClient:
    """Thin client over the Runner's engagement and scan endpoints."""

    def __init__(self, base_url: str, http_client: httpx.Client | None = None):
        self._owns = http_client is None
        self._http = http_client or httpx.Client(base_url=base_url.rstrip("/"), timeout=30.0)

    def close(self) -> None:
        if self._owns:
            self._http.close()

    def _headers(self, grant: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {grant}"}

    def _post(self, path: str, grant: str, body: dict) -> dict:
        resp = self._http.post(path, json=body, headers=self._headers(grant))
        if resp.status_code != 200:
            raise RunnerError(f"{path}: {resp.status_code} {resp.text}")
        result: dict = resp.json()
        return result

    def _get(self, path: str, grant: str) -> dict:
        resp = self._http.get(path, headers=self._headers(grant))
        if resp.status_code != 200:
            raise RunnerError(f"{path}: {resp.status_code} {resp.text}")
        result: dict = resp.json()
        return result

    def create_engagement(self, grant: str, scope: dict, ttl_minutes: int = 480) -> dict:
        # The approver identity is derived server-side from the verified grant, so the
        # client does not (and cannot) supply an authorized_by.
        body: dict[str, object] = {"scope": scope, "ttl_minutes": ttl_minutes}
        return self._post("/v1/engagements", grant, body)

    def get_engagement(self, grant: str, engagement_id: str) -> dict:
        return self._get(f"/v1/engagements/{engagement_id}", grant)

    def close_engagement(self, grant: str, engagement_id: str) -> dict:
        return self._post(f"/v1/engagements/{engagement_id}/close", grant, {})

    def create_scan(
        self, grant: str, engagement_id: str, target: str, track: str, token: dict | None = None
    ) -> dict:
        body: dict[str, object] = {
            "engagement_id": engagement_id,
            "target": target,
            "track": track,
        }
        if token is not None:
            body["token"] = token
        return self._post("/v1/scans", grant, body)

    def get_scan(self, grant: str, scan_id: str) -> dict:
        return self._get(f"/v1/scans/{scan_id}", grant)

    def get_evidence(self, grant: str, scan_id: str) -> dict:
        """Fetch the signed evidence bundle for a scan (verify it with the public key)."""
        return self._get(f"/v1/scans/{scan_id}/evidence", grant)

    def list_scans(self, grant: str) -> dict:
        return self._get("/v1/scans", grant)

    def wait_for_scan(
        self, grant: str, scan_id: str, timeout: float = 30.0, interval: float = 0.2
    ) -> dict:
        """Poll get_scan until the scan leaves the queued state, or timeout."""
        deadline = time.monotonic() + timeout
        while True:
            scan = self.get_scan(grant, scan_id)
            if scan.get("status") != "queued" or time.monotonic() >= deadline:
                return scan
            time.sleep(interval)
