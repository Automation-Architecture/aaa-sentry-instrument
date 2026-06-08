"""
Sentry ``before_send`` secret/PII scrubber for AAA FastAPI backends.

This file IS the canonical source for the package. If you need to change
scrubbing logic, change it here and keep the JS twin (``src/scrub.ts``) in
sync.

⚠️  SYNC REQUIREMENT: The regex source strings and secret-key list in this
file must stay byte-identical to the JS twin (``src/scrub.ts``).  A comment
in that file mirrors this requirement.  Whenever you add or remove a key,
update BOTH files in the same commit.

Strips PII and secrets from every Sentry event payload before it leaves the
process.  Four categories of sensitive data are scrubbed:

1. **Bearer tokens** — ``Authorization: Bearer <token>`` / bare ``Bearer <x>``
   anywhere in a string; scrubbed to ``Bearer [REDACTED]``.
   Applied FIRST so the full token is removed before the key-name rule can
   partially match ``authorization``.

2. **Secret/credential parameters by key name** — wherever a ``key=value``,
   ``"key":"value"``, or ``key: value`` pattern appears (query strings, URLs,
   JSON-ish text, log lines).  Redacts the VALUE, keeps the key.  Covered
   keys (case-insensitive, matched with ``\\b`` word boundary):
     access_token, refresh_token, id_token, client_secret, private_key,
     api_key, apikey, sessionid, password, passwd, session, secret,
     token, csrf, code, state, auth, pwd, key
   (``authorization`` is handled exclusively by the Bearer rule — including
   it here would strip the word "Bearer" after rule 1 already placed it.)
   Longer keys are listed before shorter stems so that ``\\b`` anchoring is
   belt-and-suspenders (e.g. ``access_token`` before ``token``).

3. **Email addresses** — RFC-5322-ish ``user@host.tld``; scrubbed to
   ``[REDACTED_EMAIL]``.

4. **UUID-v4 / long-hex token-like values** (e.g. ``comment_token``) —
   pattern ``xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx``; scrubbed to
   ``[REDACTED_TOKEN]``.  The version nibble (4) and variant bits ([89ab])
   prevent matching unrelated hex strings like git SHAs.

Non-secret parameters (``redirect_uri``, ``page``, ``id``, ``utm_source``,
etc.) are NOT redacted.

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

# UUID-v4 / token-like pattern.  Anchored on version nibble (4) and variant
# bits ([89ab]) to avoid matching git SHAs and other hex strings.
# Formerly described as comment_token only; retained name for backwards compat.
COMMENT_TOKEN_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# IPv4 address pattern — matches exactly four octets (0-255) delimited by
# word boundaries.  Requires all four octets so version strings like `1.2.3`
# are NOT matched.  Applied in _scrub_string to catch IPs in messages, URLs,
# and breadcrumb data.
#
# ⚠️  Keep the source string byte-identical to the JS twin (src/scrub.ts).
IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Bearer token pattern — matches `Bearer <token>` and replaces the token with
# [REDACTED].  Must run BEFORE the key-name rule so the full
# `Authorization: Bearer <x>` is handled before `authorization` can partially
# match.
BEARER_RE = re.compile(
    r"\bBearer\s+([^\s\"',;}\]]+)",
    re.IGNORECASE,
)

# Secret/credential parameter by key name.
# Matches: key=value, "key":"value", "key": "value", key: value, etc.
# The \b word-boundary on the key prevents substrings (e.g. `real_estate`→`state`).
# Value stops at the first quote/whitespace/delimiter so innocent params
# (page=2, redirect_uri=...) aren't touched unless they follow a secret key.
#
# Key list (longest-stem-first for belt-and-suspenders, \b does real work):
#   access_token, refresh_token, id_token, client_secret, private_key,
#   api_key, apikey, sessionid, password, passwd, session, secret, token,
#   csrf, code, state, auth, pwd, key
#
# NOTE: `authorization` is intentionally absent — Bearer handles auth headers
# end-to-end.  Including `authorization` here would strip the word "Bearer"
# from the output after the Bearer rule already replaced the token value.
#
# ⚠️  Keep this list in sync with src/scrub.ts (same keys, same order).
SECRET_KEY_RE = re.compile(
    r"\b(access_token|refresh_token|id_token|client_secret|private_key|api_key|apikey|sessionid|password|passwd|session|secret|token|csrf|code|state|auth|pwd|key)\b"
    r"(\s*[\"']?\s*[:=]\s*[\"']?)([^\"'&\s,;}\]]+)",
    re.IGNORECASE,
)


def _scrub_string(value: str) -> str:
    """Replace PII and secret patterns in ``value`` with safe placeholders.

    Application order:
    1. Bearer tokens — first so full `Authorization: Bearer <x>` is handled
       before the key-name rule can partially match `authorization`.
    2. Secret/credential params by key name (value redacted, key kept).
    3. Email addresses.
    4. UUID-v4 / token-like patterns.
    5. IPv4 addresses in free-text (messages, URLs, breadcrumbs).
       Requires all four octets — does NOT match version strings like 1.2.3.
    """
    # 1. Bearer tokens
    value = BEARER_RE.sub(r"Bearer [REDACTED]", value)
    # 2. Secret/credential params by key name
    value = SECRET_KEY_RE.sub(r"\1\2[REDACTED]", value)
    # 3. Email addresses
    value = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    # 4. UUID-v4 / token-like patterns
    value = COMMENT_TOKEN_RE.sub("[REDACTED_TOKEN]", value)
    # 5. IPv4 addresses
    value = IPV4_RE.sub("[REDACTED_IP]", value)
    return value


def _scrub_any(value: Any, _visited: set[int] | None = None) -> Any:
    """Recursively walk ``value`` and scrub any string member.

    An ``id()``-based visited set guards against infinite recursion on
    circular object graphs — any container already on the walk stack is
    returned unmodified.
    """
    if isinstance(value, str):
        return _scrub_string(value)
    if isinstance(value, (list, tuple, dict)):
        visited = _visited if _visited is not None else set()
        oid = id(value)
        if oid in visited:
            return value  # cycle detected — stop recursion
        visited.add(oid)
        if isinstance(value, list):
            result_list = [_scrub_any(item, visited) for item in value]
            visited.discard(oid)
            return result_list
        if isinstance(value, tuple):
            result_tuple = tuple(_scrub_any(item, visited) for item in value)
            visited.discard(oid)
            return result_tuple
        # dict
        result_dict = {key: _scrub_any(val, visited) for key, val in value.items()}
        visited.discard(oid)
        return result_dict
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

    # User identity — scrub identity fields that carry PII.
    # ``user.id`` is retained as a non-PII opaque identifier unless it looks
    # like an email address, in which case it is also redacted.
    user = event.get("user")
    if isinstance(user, dict):
        if "ip_address" in user:
            user["ip_address"] = "[REDACTED_IP]"
        if "email" in user:
            user["email"] = "[REDACTED_EMAIL]"
        if "username" in user:
            user["username"] = "[REDACTED]"
        if "name" in user:
            user["name"] = "[REDACTED]"
        # Redact user.id only when it looks like an email.
        if isinstance(user.get("id"), str) and EMAIL_RE.search(user["id"]):
            user["id"] = "[REDACTED_EMAIL]"

    return event


__all__ = [
    "scrub_pii",
    "_scrub_string",
    "_scrub_any",
    "EMAIL_RE",
    "COMMENT_TOKEN_RE",
    "BEARER_RE",
    "SECRET_KEY_RE",
    "IPV4_RE",
]
