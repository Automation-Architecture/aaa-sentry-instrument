"""
House-default Sentry initialization for AAA FastAPI backends.

Call ``init_sentry()`` at the top of your ``main.py``, before constructing
the FastAPI app, so the SDK's integrations can hook the framework at import
time.

The function is a no-op when ``SENTRY_DSN`` is unset — the service runs
normally without Sentry configured (e.g. local dev, CI before the secret is
wired).

Usage::

    from aaa_sentry_instrument import init_sentry
    init_sentry()

    app = FastAPI(...)

Environment variables
---------------------
SENTRY_DSN
    Required. Sentry Data Source Name. No-op when absent.
RAILWAY_ENVIRONMENT
    Optional. Defaults to ``"production"`` when absent.
RAILWAY_GIT_COMMIT_SHA
    Optional. Injected automatically on Railway; omit locally.
"""

from __future__ import annotations

import os
from typing import Any


def init_sentry(
    *,
    traces_sample_rate: float | None = None,
    extra_integrations: list[Any] | None = None,
) -> None:
    """Initialise Sentry with AAA house defaults.

    Parameters
    ----------
    traces_sample_rate:
        Override the default sample rate (0.1 in production).
        Pass ``1.0`` for 100% sampling in a staging environment.
    extra_integrations:
        Additional ``sentry_sdk.Integration`` instances to merge with the
        house defaults (``FastApiIntegration``, ``AsyncioIntegration``).
    """
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return  # silent no-op — safe for local dev / CI

    import sentry_sdk
    from sentry_sdk.integrations.asyncio import AsyncioIntegration
    from sentry_sdk.integrations.fastapi import FastApiIntegration

    from .scrub import scrub_pii

    integrations: list[Any] = [
        FastApiIntegration(),
        AsyncioIntegration(),
    ]
    if extra_integrations:
        integrations.extend(extra_integrations)

    # Default: 10% sampling in production; allow override.
    if traces_sample_rate is None:
        traces_sample_rate = 0.1

    sentry_sdk.init(
        dsn=dsn,
        integrations=integrations,
        traces_sample_rate=traces_sample_rate,
        environment=os.environ.get("RAILWAY_ENVIRONMENT", "production"),
        release=os.environ.get("RAILWAY_GIT_COMMIT_SHA"),
        before_send=scrub_pii,
        # Do not attach request bodies by default — contact endpoints
        # may contain email addresses. Use set_context() per-transaction
        # when debugging requires it.
        send_default_pii=False,
    )
