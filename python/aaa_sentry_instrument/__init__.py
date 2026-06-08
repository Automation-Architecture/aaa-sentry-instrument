"""
aaa-sentry-instrument — Python package public API.

Install from GitHub::

    pip install "git+https://github.com/Automation-Architecture/aaa-sentry-instrument.git#subdirectory=python"

Usage::

    from aaa_sentry_instrument import init_sentry, scrub_pii
    init_sentry()   # call before constructing FastAPI app
"""

from .init import init_sentry
from .scrub import scrub_pii, _scrub_string, _scrub_any, EMAIL_RE, COMMENT_TOKEN_RE

__all__ = [
    "init_sentry",
    "scrub_pii",
    "_scrub_string",
    "_scrub_any",
    "EMAIL_RE",
    "COMMENT_TOKEN_RE",
]
