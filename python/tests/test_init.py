"""
Tests for ``aaa_sentry_instrument.init_sentry`` — v0.1.1 robustness.

Verifies:
- DSN with surrounding whitespace is trimmed before the env-gate check AND
  before being passed to ``sentry_sdk.init``.
- Whitespace-only DSN is treated as absent (no-op — sentry_sdk.init not called).
- Absent DSN is also a no-op.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import importlib
import sys


def _call_init_sentry(monkeypatch, dsn_value: str | None) -> MagicMock:
    """
    Helper: set SENTRY_DSN to *dsn_value* (or remove it if None), then call
    ``init_sentry()``.  Returns the mock for ``sentry_sdk.init`` so callers
    can assert on it.

    ``sentry_sdk`` is imported lazily *inside* ``init_sentry``, so we patch
    it via ``sys.modules`` before the function runs.
    """
    mock_sdk = MagicMock()
    mock_sdk.integrations.asyncio.AsyncioIntegration = MagicMock
    mock_sdk.integrations.fastapi.FastApiIntegration = MagicMock

    # Ensure a fresh import of the module under test so any module-level state
    # is reset between calls.
    mod_name = "aaa_sentry_instrument.init"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    # Patch the lazily-imported sentry_sdk that init_sentry() imports at call time.
    with patch.dict("sys.modules", {"sentry_sdk": mock_sdk,
                                    "sentry_sdk.integrations.asyncio": mock_sdk.integrations.asyncio,
                                    "sentry_sdk.integrations.fastapi": mock_sdk.integrations.fastapi}):
        if dsn_value is None:
            monkeypatch.delenv("SENTRY_DSN", raising=False)
        else:
            monkeypatch.setenv("SENTRY_DSN", dsn_value)

        mod = importlib.import_module(mod_name)
        mod.init_sentry()

    return mock_sdk.init


REAL_DSN = "https://abc123@o0.ingest.sentry.io/123"


# ---------------------------------------------------------------------------
# DSN trimming — gate behaviour
# ---------------------------------------------------------------------------


def test_dsn_with_leading_trailing_whitespace_is_used(monkeypatch) -> None:
    """A padded DSN must pass the gate and arrive at sentry_sdk.init trimmed."""
    mock_init = _call_init_sentry(monkeypatch, f"  {REAL_DSN}  ")
    mock_init.assert_called_once()
    _, kwargs = mock_init.call_args
    assert kwargs["dsn"] == REAL_DSN, f"Expected trimmed DSN, got: {kwargs['dsn']!r}"


def test_dsn_trimmed_value_passed_to_sdk(monkeypatch) -> None:
    """The value reaching sentry_sdk.init must not contain surrounding whitespace."""
    mock_init = _call_init_sentry(monkeypatch, f"\t{REAL_DSN}\n")
    mock_init.assert_called_once()
    _, kwargs = mock_init.call_args
    assert kwargs["dsn"] == REAL_DSN


def test_whitespace_only_dsn_is_no_op(monkeypatch) -> None:
    """A whitespace-only DSN must be treated as absent — sentry_sdk.init not called."""
    mock_init = _call_init_sentry(monkeypatch, "   ")
    mock_init.assert_not_called()


def test_empty_dsn_is_no_op(monkeypatch) -> None:
    """An empty string DSN must also be a no-op."""
    mock_init = _call_init_sentry(monkeypatch, "")
    mock_init.assert_not_called()


def test_absent_dsn_is_no_op(monkeypatch) -> None:
    """When SENTRY_DSN is not set at all, sentry_sdk.init must not be called."""
    mock_init = _call_init_sentry(monkeypatch, None)
    mock_init.assert_not_called()
