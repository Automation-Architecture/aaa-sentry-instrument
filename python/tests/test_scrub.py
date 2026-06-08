"""
Tests for ``aaa_sentry_instrument.scrub_pii`` and its helpers.

Ported from ``Automation-Architecture/aaa-client-dashboard``
``backend/tests/test_sentry_scrubber.py``.

Covers:
- Email addresses (replaced with ``[EMAIL]``)
- comment_token UUIDs (replaced with ``[COMMENT_TOKEN]``)
- Deep nesting (extra, tags, nested dicts, lists, tuples)
- All well-known event fields: message, request, exception, breadcrumbs,
  logentry, extra, tags
"""

from __future__ import annotations

from aaa_sentry_instrument.scrub import (
    COMMENT_TOKEN_RE,
    EMAIL_RE,
    _scrub_string,
    _scrub_any,
    scrub_pii,
)

# A realistic UUID v4 comment_token.
SAMPLE_TOKEN = "a1b2c3d4-e5f6-4789-a012-b3c4d5e6f789"

# A realistic email address.
SAMPLE_EMAIL = "client@acme-corp.io"


# ---------------------------------------------------------------------------
# Exported regex patterns — pinned so a regex change is caught explicitly
# ---------------------------------------------------------------------------


def test_email_re_is_exported() -> None:
    assert EMAIL_RE.pattern == r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"


def test_comment_token_re_is_exported() -> None:
    assert COMMENT_TOKEN_RE.pattern == (
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    )


# ---------------------------------------------------------------------------
# _scrub_string — unit tests
# ---------------------------------------------------------------------------


def test_scrub_string_redacts_email() -> None:
    assert _scrub_string(f"Contact from {SAMPLE_EMAIL}") == "Contact from [EMAIL]"


def test_scrub_string_redacts_comment_token() -> None:
    assert _scrub_string(f"token={SAMPLE_TOKEN}") == "token=[COMMENT_TOKEN]"


def test_scrub_string_leaves_non_email_untouched() -> None:
    assert _scrub_string("hello world") == "hello world"
    assert _scrub_string("/api/projects/fas/stages") == "/api/projects/fas/stages"


def test_scrub_string_leaves_non_uuid_untouched() -> None:
    assert _scrub_string("abc123def456") == "abc123def456"
    # UUID v1-style — version nibble is 1, not 4
    non_v4_uuid = "a1b2c3d4-e5f6-1789-c012-b3c4d5e6f789"
    assert _scrub_string(non_v4_uuid) == non_v4_uuid


def test_scrub_string_redacts_multiple_occurrences() -> None:
    value = f"{SAMPLE_EMAIL} sent comment {SAMPLE_TOKEN}"
    scrubbed = _scrub_string(value)
    assert SAMPLE_EMAIL not in scrubbed
    assert SAMPLE_TOKEN not in scrubbed
    assert "[EMAIL]" in scrubbed
    assert "[COMMENT_TOKEN]" in scrubbed


# ---------------------------------------------------------------------------
# _scrub_any — deep nesting
# ---------------------------------------------------------------------------


def test_scrub_any_handles_primitives() -> None:
    assert _scrub_any(42) == 42
    assert _scrub_any(True) is True
    assert _scrub_any(None) is None


def test_scrub_any_scrubs_string() -> None:
    assert _scrub_any(SAMPLE_EMAIL) == "[EMAIL]"


def test_scrub_any_scrubs_list() -> None:
    result = _scrub_any([SAMPLE_EMAIL, "safe"])
    assert result == ["[EMAIL]", "safe"]


def test_scrub_any_scrubs_tuple() -> None:
    result = _scrub_any((SAMPLE_EMAIL, "safe"))
    assert result == ("[EMAIL]", "safe")


def test_scrub_any_scrubs_nested_dict() -> None:
    result = _scrub_any({
        "level1": {
            "level2": {"email": SAMPLE_EMAIL, "token": SAMPLE_TOKEN, "safe": "keep"}
        }
    })
    assert result["level1"]["level2"]["email"] == "[EMAIL]"
    assert result["level1"]["level2"]["token"] == "[COMMENT_TOKEN]"
    assert result["level1"]["level2"]["safe"] == "keep"


# ---------------------------------------------------------------------------
# scrub_pii — full event scrubbing
# ---------------------------------------------------------------------------


def test_scrub_event_redacts_all_known_locations() -> None:
    event: dict = {
        "request": {
            "url": f"https://api.dashboard.ai/api/contact?ref={SAMPLE_EMAIL}",
            "query_string": f"email={SAMPLE_EMAIL}",
            "data": {
                "email": SAMPLE_EMAIL,
                "comment_token": SAMPLE_TOKEN,
                "name": "keep-me",
            },
        },
        "exception": {
            "values": [
                {
                    "type": "ValueError",
                    "value": (
                        f"Invalid payload from {SAMPLE_EMAIL} token={SAMPLE_TOKEN}"
                    ),
                }
            ]
        },
        "breadcrumbs": {
            "values": [
                {
                    "category": "http",
                    "message": f"POST /api/contact from {SAMPLE_EMAIL}",
                    "data": {
                        "url": f"https://api.dashboard.ai/api/contact?e={SAMPLE_EMAIL}",
                        "method": "POST",
                    },
                }
            ]
        },
        "logentry": {
            "message": "Contact from %s",
            "formatted": f"Contact from {SAMPLE_EMAIL} token={SAMPLE_TOKEN}",
        },
        "extra": {
            "submitter_email": SAMPLE_EMAIL,
            "comment_ref": SAMPLE_TOKEN,
        },
        "tags": {
            "user_email": SAMPLE_EMAIL,
        },
    }

    scrubbed = scrub_pii(event, None)
    assert scrubbed is event  # in-place mutation

    rendered = repr(scrubbed)
    assert SAMPLE_EMAIL not in rendered, "Scrubber left an email: " + rendered
    assert SAMPLE_TOKEN not in rendered, "Scrubber left a token: " + rendered
    assert "[EMAIL]" in rendered
    assert "[COMMENT_TOKEN]" in rendered

    # Static fields must survive
    assert scrubbed["request"]["data"]["name"] == "keep-me"
    assert scrubbed["breadcrumbs"]["values"][0]["data"]["method"] == "POST"


def test_scrub_event_is_safe_on_empty_event() -> None:
    assert scrub_pii({}, None) == {}


def test_scrub_event_tolerates_missing_subtrees() -> None:
    event = {"level": "error", "message": "boom"}
    assert scrub_pii(event, None) is event


def test_scrub_event_no_mutation_when_no_pii() -> None:
    event: dict = {
        "request": {"url": "https://api.dashboard.ai/health"},
        "extra": {"slug": "fas"},
    }
    scrubbed = scrub_pii(event, None)
    assert scrubbed["request"]["url"] == "https://api.dashboard.ai/health"
    assert scrubbed["extra"]["slug"] == "fas"


def test_scrub_event_redacts_top_level_message() -> None:
    event: dict = {
        "message": f"Contact submitted by {SAMPLE_EMAIL} ref={SAMPLE_TOKEN}",
    }
    scrubbed = scrub_pii(event, None)
    assert SAMPLE_EMAIL not in scrubbed["message"]
    assert SAMPLE_TOKEN not in scrubbed["message"]
    assert "[EMAIL]" in scrubbed["message"]
    assert "[COMMENT_TOKEN]" in scrubbed["message"]


def test_scrub_event_stacktrace_vars() -> None:
    """Stack frame locals are scrubbed."""
    event: dict = {
        "exception": {
            "values": [{
                "type": "RuntimeError",
                "value": "oops",
                "stacktrace": {
                    "frames": [
                        {"vars": {"email": SAMPLE_EMAIL, "count": 1}},
                    ]
                },
            }]
        }
    }
    scrubbed = scrub_pii(event, None)
    frame_vars = scrubbed["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]
    assert frame_vars["email"] == "[EMAIL]"
    assert frame_vars["count"] == 1  # non-string preserved
