"""
Tests for ``aaa_sentry_instrument.scrub_pii`` and its helpers.

Ported from ``Automation-Architecture/aaa-client-dashboard``
``backend/tests/test_sentry_scrubber.py`` and extended with comprehensive
secret-by-key-name + Bearer redaction tests.

Covers:
- Email addresses (replaced with ``[REDACTED_EMAIL]``)
- UUID-v4 / token-like values (replaced with ``[REDACTED_TOKEN]``)
- Bearer token header values (replaced with ``Bearer [REDACTED]``)
- Secret/credential params by key name (value replaced with ``[REDACTED]``)
- Non-secret params survive unredacted (``redirect_uri``, ``page``, etc.)
- Deep nesting (extra, tags, nested dicts, lists, tuples)
- All well-known event fields: message, request, exception, breadcrumbs,
  logentry, extra, tags

⚠️  Keep in sync with __tests__/scrub.test.ts — same key list, same
placeholder strings, same behavioral assertions.
"""

from __future__ import annotations

from aaa_sentry_instrument.scrub import (
    COMMENT_TOKEN_RE,
    EMAIL_RE,
    BEARER_RE,
    IPV4_RE,
    SECRET_KEY_RE,
    _scrub_string,
    _scrub_any,
    scrub_pii,
)

# A realistic UUID v4 (not relying on UUID shape for key-name tests).
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


def test_bearer_re_and_secret_key_re_are_exported() -> None:
    assert BEARER_RE is not None
    assert SECRET_KEY_RE is not None


def test_ipv4_re_pattern_is_pinned() -> None:
    """IPV4_RE source must stay byte-identical to the JS twin (src/scrub.ts)."""
    assert IPV4_RE.pattern == r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


# ---------------------------------------------------------------------------
# _scrub_string — email + UUID-token (legacy behaviours)
# ---------------------------------------------------------------------------


def test_scrub_string_redacts_email() -> None:
    assert _scrub_string(f"Contact from {SAMPLE_EMAIL}") == "Contact from [REDACTED_EMAIL]"


def test_scrub_string_redacts_uuid_token() -> None:
    result = _scrub_string(f"token={SAMPLE_TOKEN}")
    assert SAMPLE_TOKEN not in result
    assert "[REDACTED" in result


def test_scrub_string_leaves_non_email_untouched() -> None:
    assert _scrub_string("hello world") == "hello world"
    assert _scrub_string("/api/projects/fas/stages") == "/api/projects/fas/stages"


def test_scrub_string_leaves_non_v4_uuid_untouched() -> None:
    assert _scrub_string("abc123def456") == "abc123def456"
    # UUID v1-style — version nibble is 1, not 4
    non_v4_uuid = "a1b2c3d4-e5f6-1789-c012-b3c4d5e6f789"
    assert _scrub_string(non_v4_uuid) == non_v4_uuid


def test_scrub_string_redacts_multiple_occurrences() -> None:
    value = f"{SAMPLE_EMAIL} sent comment {SAMPLE_TOKEN}"
    scrubbed = _scrub_string(value)
    assert SAMPLE_EMAIL not in scrubbed
    assert SAMPLE_TOKEN not in scrubbed
    assert "[REDACTED_EMAIL]" in scrubbed
    assert "[REDACTED_TOKEN]" in scrubbed


# ---------------------------------------------------------------------------
# _scrub_string — IPv4 address redaction
# ---------------------------------------------------------------------------


def test_scrub_string_redacts_ipv4_in_message() -> None:
    result = _scrub_string("Request from 203.0.113.42 failed")
    assert "203.0.113.42" not in result
    assert "[REDACTED_IP]" in result


def test_scrub_string_does_not_redact_version_string() -> None:
    result = _scrub_string("Version 1.2.3 released")
    assert result == "Version 1.2.3 released"


def test_scrub_string_redacts_ipv4_in_url() -> None:
    result = _scrub_string("https://203.0.113.42/api/data")
    assert "203.0.113.42" not in result
    assert "[REDACTED_IP]" in result


# ---------------------------------------------------------------------------
# _scrub_string — secret params by key name (plain non-UUID values)
# ---------------------------------------------------------------------------


def test_scrub_string_redacts_secret_eq_hunter2() -> None:
    result = _scrub_string("secret=hunter2")
    assert "hunter2" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_access_token_plain() -> None:
    result = _scrub_string("access_token=abc123XYZ")
    assert "abc123XYZ" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_client_secret() -> None:
    result = _scrub_string("client_secret=foo")
    assert "foo" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_password() -> None:
    result = _scrub_string("password=p@ss")
    assert "p@ss" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_code() -> None:
    result = _scrub_string("?code=authcode123&redirect_uri=https://app/cb")
    assert "authcode123" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_state() -> None:
    result = _scrub_string("state=xyz")
    assert "xyz" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_token_in_json() -> None:
    result = _scrub_string('{"token":"mySecretToken123"}')
    assert "mySecretToken123" not in result
    assert "[REDACTED]" in result


def test_scrub_string_redacts_api_key_in_query() -> None:
    result = _scrub_string("https://api.example.com?api_key=sk-live-xyz")
    assert "sk-live-xyz" not in result
    assert "[REDACTED]" in result


# ---------------------------------------------------------------------------
# _scrub_string — Bearer token
# ---------------------------------------------------------------------------


def test_scrub_string_redacts_bearer_non_uuid() -> None:
    result = _scrub_string("Authorization: Bearer sk-not-a-uuid-12345")
    assert "sk-not-a-uuid-12345" not in result
    assert "Bearer [REDACTED]" in result


def test_scrub_string_redacts_bare_bearer() -> None:
    result = _scrub_string("Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")
    assert "eyJhbGciOiJSUzI1NiJ9" not in result
    assert "Bearer [REDACTED]" in result


# ---------------------------------------------------------------------------
# _scrub_string — non-secret params survive
# ---------------------------------------------------------------------------


def test_scrub_string_redirect_uri_survives() -> None:
    result = _scrub_string("redirect_uri=https://app/cb")
    assert result == "redirect_uri=https://app/cb"


def test_scrub_string_page_survives() -> None:
    result = _scrub_string("page=2")
    assert result == "page=2"


def test_scrub_string_utm_source_survives() -> None:
    result = _scrub_string("utm_source=newsletter")
    assert result == "utm_source=newsletter"


def test_scrub_string_id_survives() -> None:
    result = _scrub_string("id=42")
    assert result == "id=42"


# ---------------------------------------------------------------------------
# _scrub_any — deep nesting
# ---------------------------------------------------------------------------


def test_scrub_any_handles_primitives() -> None:
    assert _scrub_any(42) == 42
    assert _scrub_any(True) is True
    assert _scrub_any(None) is None


def test_scrub_any_scrubs_string() -> None:
    assert _scrub_any(SAMPLE_EMAIL) == "[REDACTED_EMAIL]"


def test_scrub_any_scrubs_list() -> None:
    result = _scrub_any([SAMPLE_EMAIL, "safe"])
    assert result == ["[REDACTED_EMAIL]", "safe"]


def test_scrub_any_scrubs_tuple() -> None:
    result = _scrub_any((SAMPLE_EMAIL, "safe"))
    assert result == ("[REDACTED_EMAIL]", "safe")


def test_scrub_any_scrubs_nested_dict() -> None:
    result = _scrub_any({
        "level1": {
            "level2": {"email": SAMPLE_EMAIL, "token": SAMPLE_TOKEN, "safe": "keep"}
        }
    })
    assert result["level1"]["level2"]["email"] == "[REDACTED_EMAIL]"
    assert SAMPLE_TOKEN not in result["level1"]["level2"]["token"]
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
    assert "[REDACTED_EMAIL]" in rendered
    assert "[REDACTED" in rendered

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
    assert "[REDACTED_EMAIL]" in scrubbed["message"]
    assert "[REDACTED" in scrubbed["message"]


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
    assert frame_vars["email"] == "[REDACTED_EMAIL]"
    assert frame_vars["count"] == 1  # non-string preserved


def test_scrub_event_bearer_token_in_extra() -> None:
    """Bearer token captured in extra headers is scrubbed."""
    event: dict = {
        "extra": {
            "headers": "Authorization: Bearer sk-not-a-uuid-12345",
        }
    }
    scrubbed = scrub_pii(event, None)
    rendered = repr(scrubbed)
    assert "sk-not-a-uuid-12345" not in rendered
    assert "Bearer [REDACTED]" in rendered


def test_scrub_event_non_secret_query_params_survive() -> None:
    """Non-secret params in request URL are preserved."""
    event: dict = {
        "request": {
            "url": "https://api.dashboard.ai/oauth/callback?redirect_uri=https://app/cb&page=2",
        }
    }
    scrubbed = scrub_pii(event, None)
    url = scrubbed["request"]["url"]
    assert "redirect_uri=https://app/cb" in url
    assert "page=2" in url


# ---------------------------------------------------------------------------
# scrub_pii — user identity field scrubbing
# ---------------------------------------------------------------------------


def test_scrub_event_redacts_user_ip_address() -> None:
    event: dict = {"user": {"ip_address": "203.0.113.42"}}
    scrubbed = scrub_pii(event, None)
    assert scrubbed["user"]["ip_address"] == "[REDACTED_IP]"


def test_scrub_event_redacts_user_email() -> None:
    event: dict = {"user": {"email": SAMPLE_EMAIL}}
    scrubbed = scrub_pii(event, None)
    assert scrubbed["user"]["email"] == "[REDACTED_EMAIL]"


def test_scrub_event_redacts_user_username() -> None:
    event: dict = {"user": {"username": "jane.doe"}}
    scrubbed = scrub_pii(event, None)
    assert scrubbed["user"]["username"] == "[REDACTED]"


def test_scrub_event_leaves_plain_user_id_intact() -> None:
    event: dict = {"user": {"id": "user_abc123"}}
    scrubbed = scrub_pii(event, None)
    assert scrubbed["user"]["id"] == "user_abc123"


def test_scrub_event_redacts_email_shaped_user_id() -> None:
    event: dict = {"user": {"id": SAMPLE_EMAIL}}
    scrubbed = scrub_pii(event, None)
    assert scrubbed["user"]["id"] == "[REDACTED_EMAIL]"


def test_scrub_event_redacts_ipv4_in_message() -> None:
    event: dict = {"message": "Connection refused from 203.0.113.42"}
    scrubbed = scrub_pii(event, None)
    assert "203.0.113.42" not in scrubbed["message"]
    assert "[REDACTED_IP]" in scrubbed["message"]


def test_scrub_event_does_not_redact_version_string_in_message() -> None:
    event: dict = {"message": "Upgraded to version 1.2.3"}
    scrubbed = scrub_pii(event, None)
    assert "1.2.3" in scrubbed["message"]
