"""Structured logging + redaction tests."""

from __future__ import annotations

import io
import json
import logging

from obs import get_logger, log_event, redact


def _capture():
    buf = io.StringIO()
    return get_logger("wraith.test", stream=buf, level=logging.DEBUG), buf


def test_log_event_emits_json_with_fields():
    logger, buf = _capture()
    log_event(logger, logging.INFO, "job.start", engine="skillspector", target="repo")
    rec = json.loads(buf.getvalue().strip())
    assert rec["message"] == "job.start" and rec["level"] == "INFO"
    assert rec["fields"] == {"engine": "skillspector", "target": "repo"}


def test_redact_bearer_sk_and_keyed_values():
    assert "REDACTED" in redact("Authorization: Bearer abcdef123456")
    assert "REDACTED" in redact("key sk-ABCDEFGH12345678")
    assert "REDACTED" in redact('api_key="supersecretvalue"')
    assert "REDACTED" in redact("password: hunter2hunter")


def test_redact_leaves_hashes_alone():
    h = "a" * 64
    assert h in redact(f"fingerprint {h}")


def test_redact_env_secret_value(monkeypatch):
    monkeypatch.setenv("WRAITH_RESULT_KEY", "topsecretmaster")
    out = redact("using key topsecretmaster now")
    assert "topsecretmaster" not in out and "REDACTED" in out


def test_logger_output_is_redacted(monkeypatch):
    monkeypatch.setenv("WRAITH_SIGNING_KEY", "signsignsign")
    logger, buf = _capture()
    log_event(logger, logging.INFO, "signed", key="signsignsign")
    assert "signsignsign" not in buf.getvalue()


def test_get_logger_is_idempotent():
    buf = io.StringIO()
    get_logger("wraith.test.idem", stream=buf)
    logger = get_logger("wraith.test.idem", stream=buf)
    assert len(logger.handlers) == 1
