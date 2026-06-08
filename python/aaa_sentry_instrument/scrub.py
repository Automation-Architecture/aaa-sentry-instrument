"""
Sentry ``before_send`` scrubber for AAA FastAPI backends.

Lifted verbatim from ``Automation-Architecture/aaa-client-dashboard``
``backend/sentry_scrubber.py`` — this file IS the canonical source for
the package. If you need to change scrubbing logic, change it here and
keep the JS twin (``src/scrub.ts``) in sync.

Strips PII from every Sentry event payload before it leaves the process.
Two categories of sensitive data flow through AAA services:

1. **Email addresses** — submitted via contact-form / API payloads.
   Pattern: standard ``user@host.tld`` form; scrubbed to ``[EMAIL]``.

2. **comment_token** — UUID v4 stored in ``project_client_comments`` and
   used as an edit/delete bearer credential on comment endpoints.
   Pattern: ``xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx``; scrubbed to
   ``[COMMENT_TOKEN]``.

We walk the event dict and scrub these patterns wherever they can surface:
- exception values + messages
- request URL / query string / data
- breadcrumb messages + data
- extra / tags dicts
- logentry

Unknown fields are left untouched to minimise blast radius.

The scrubber accepts and mutates the event dict in place (Sentry's
``before_send`` hook expects the mutated dict back, not ``None`` — returning
``None`` would *drop* the event).
"""

from __future__ import annotations

import re
from typing import Any

# RFC-5322-ish email pattern — conservative; catches the common
# `user@example.com` form without trying to be a full RFC validator.
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# comment_token is a UUID v4 (see `project_client_comments.comment_token`).
# The bracket notation anchors the version nibble (4) and the variant bits
# ([89ab]) so we don't scrub unrelated hex strings like git SHAs.
COMMENT_TOKEN_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _scrub_string(value: str) -> str:
    """Replace PII patterns in ``value`` with safe placeholders."""
    value = EMAIL_RE.sub("[EMAIL]", value)
    value = COMMENT_TOKEN_RE.sub("[COMMENT_TOKEN]", value)
    return value


def _scrub_any(value: Any) -> Any:
    """Recursively walk ``value`` and scrub any string member."""
    if isinstance(value, str):
        return _scrub_string(value)
    if isinstance(value, list):
        return [_scrub_any(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_any(item) for item in value)
    if isinstance(value, dict):
        return {key: _scrub_any(val) for key, val in value.items()}
    return value


def scrub_pii(event: Any, hint: dict | None = None) -> Any:
    """Sentry ``before_send`` hook — scrub PII from every event field.

    Visits the well-known locations where PII can land:

      * ``event['message']`` (top-level event message)
      * ``event['request']['url']`` / ``['query_string']`` / ``['data']``
      * ``event['exception']['values'][*]['value']`` (exception messages)
      * ``event['breadcrumbs']['values'][*]`` — both ``message`` + ``data``
      * ``event['extra']``
      * ``event['tags']``
      * ``event['logentry']['message']`` / ``['formatted']`` / ``['params']``

    Mutates the top-level ``event`` dict in place and returns it, satisfying
    Sentry's ``before_send`` contract. Nested containers (dicts, lists,
    tuples) are rebuilt by ``_scrub_any`` as it walks them; strings are
    replaced with scrubbed copies. Returning ``None`` would drop the event
    entirely — the caller must return the mutated dict, not ``None``.
    """
    del hint  # unused; Sentry passes it for callers that need raw exc info

    if not isinstance(event, dict):
        return event  # pragma: no cover — defensive only

    # Top-level message
    if "message" in event:
        event["message"] = _scrub_any(event["message"])

    # Request metadata
    request = event.get("request")
    if isinstance(request, dict):
        for key in ("url", "query_string", "data"):
            if key in request:
                request[key] = _scrub_any(request[key])

    # Exception values (messages + stack frame locals, if any)
    exception = event.get("exception")
    if isinstance(exception, dict):
        values = exception.get("values")
        if isinstance(values, list):
            for exc_entry in values:
                if isinstance(exc_entry, dict):
                    if "value" in exc_entry:
                        exc_entry["value"] = _scrub_any(exc_entry["value"])
                    stacktrace = exc_entry.get("stacktrace")
                    if isinstance(stacktrace, dict):
                        frames = stacktrace.get("frames")
                        if isinstance(frames, list):
                            for frame in frames:
                                if isinstance(frame, dict) and "vars" in frame:
                                    frame["vars"] = _scrub_any(frame["vars"])

    # Breadcrumbs — messages + data payloads
    breadcrumbs = event.get("breadcrumbs")
    if isinstance(breadcrumbs, dict):
        values = breadcrumbs.get("values")
        if isinstance(values, list):
            for crumb in values:
                if isinstance(crumb, dict):
                    if "message" in crumb:
                        crumb["message"] = _scrub_any(crumb["message"])
                    if "data" in crumb:
                        crumb["data"] = _scrub_any(crumb["data"])

    # Logentry (from the logging integration)
    logentry = event.get("logentry")
    if isinstance(logentry, dict):
        for key in ("message", "formatted", "params"):
            if key in logentry:
                logentry[key] = _scrub_any(logentry[key])

    # Extra + tags — arbitrary user-supplied context
    if "extra" in event:
        event["extra"] = _scrub_any(event["extra"])
    if "tags" in event:
        event["tags"] = _scrub_any(event["tags"])

    return event


__all__ = ["scrub_pii", "_scrub_string", "_scrub_any", "EMAIL_RE", "COMMENT_TOKEN_RE"]
