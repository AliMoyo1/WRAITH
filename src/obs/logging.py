"""Structured, secret-redacting logging for WRAITH.

Emits one JSON object per line. A redaction pass runs on every record so raw
secrets never reach a log sink (WRAITH.md scanner self-protection: "log scanner
activity without storing raw secrets").

Redaction covers:
  * the live values of WRAITH's own secret environment variables, and
  * common secret shapes: Bearer tokens, sk-/AKIA-style keys, and
    key=value pairs whose key looks like a secret.

It deliberately does not redact long hex/base64 strings wholesale, so legitimate
hashes and fingerprints stay readable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import UTC, datetime

_REDACTED = "***REDACTED***"
_SECRET_ENV_KEYS = ("WRAITH_SIGNING_KEY", "WRAITH_RESULT_KEY")

_PATTERNS = [
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{6,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # key=value / key: value where the key name looks sensitive
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|authorization)"
               r'(["\']?\s*[:=]\s*["\']?)([^\s"\',}]{6,})'),
]


def redact(text: str) -> str:
    """Return text with known secret shapes and live secret env values removed."""
    for key in _SECRET_ENV_KEYS:
        value = os.environ.get(key)
        if value and len(value) >= 6:
            text = text.replace(value, _REDACTED)
    for pat in _PATTERNS:
        if pat.groups >= 3:
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", text)
        else:
            text = pat.sub(_REDACTED, text)
    return text


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict) and fields:
            payload["fields"] = fields
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str, sort_keys=True))


def get_logger(name: str = "wraith", stream=None, level: int = logging.INFO) -> logging.Logger:
    """Return a logger that emits redacted JSON lines to `stream` (default stderr).

    Idempotent: replaces existing handlers so repeated calls do not duplicate output.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(RedactingJsonFormatter())
    logger.addHandler(handler)
    return logger


def configure_root(level: int = logging.INFO) -> logging.Logger:
    return get_logger("wraith", level=level)


def log_event(logger: logging.Logger, level: int, message: str, **fields: object) -> None:
    """Log `message` with structured `fields` attached to the JSON record."""
    logger.log(level, message, extra={"fields": fields})
