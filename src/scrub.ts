/**
 * Shared Sentry PII / secret scrubber for AAA web apps.
 *
 * This file IS the canonical source for the package. If you need to change
 * scrubbing logic, change it here and keep the Python twin
 * (`python/aaa_sentry_instrument/scrub.py`) in sync.
 *
 * ⚠️  SYNC REQUIREMENT: The regex source strings and secret-key list in this
 * file must stay byte-identical to the Python twin (`scrub.py`).  A comment
 * in that file mirrors this requirement.  Whenever you add or remove a key,
 * update BOTH files in the same commit.
 *
 * Four categories of sensitive data are scrubbed:
 *
 * 1. **Bearer tokens** — `Authorization: Bearer <token>` / bare `Bearer <x>`
 *    anywhere in a string; scrubbed to `Bearer [REDACTED]`.
 *    Applied FIRST so the full token (not just the word "Bearer") is removed
 *    before the key-name rule can partially match `authorization`.
 *
 * 2. **Secret/credential parameters by key name** — wherever a
 *    `key=value`, `"key":"value"`, or `key: value` pattern appears (query
 *    strings, URLs, JSON-ish text, log lines).  Redacts the VALUE, keeps the
 *    key.  Covered keys (case-insensitive, matched with `\b` word boundary):
 *      access_token, refresh_token, id_token, client_secret, private_key,
 *      api_key, apikey, sessionid, password, passwd, session, secret,
 *      token, csrf, code, state, auth, pwd, key
 *    (`authorization` is handled exclusively by the Bearer rule — including
 *    it here would strip the word "Bearer" after rule 1 already placed it.)
 *    Longer keys are listed before shorter stems so that `\b` anchoring is
 *    belt-and-suspenders (e.g. `access_token` before `token`).
 *
 * 3. **Email addresses** — RFC-5322-ish `user@host.tld`; scrubbed to
 *    `[REDACTED_EMAIL]`.
 *
 * 4. **UUID-v4 / long-hex token-like values** (e.g. `comment_token`) —
 *    pattern `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`; scrubbed to
 *    `[REDACTED_TOKEN]`.  The version nibble (4) and variant bits ([89ab])
 *    prevent matching unrelated hex strings like git SHAs.
 *
 * Non-secret parameters (`redirect_uri`, `page`, `id`, `utm_source`, etc.)
 * are NOT redacted.
 *
 * Usage — import `scrubEvent` into each Sentry config file:
 *
 * ```ts
 * import { scrubEvent } from "aaa-sentry-instrument";
 *
 * Sentry.init({
 *   beforeSend(event) { return scrubEvent(event); },
 * });
 * ```
 */

import type { ErrorEvent } from "@sentry/nextjs";

// RFC-5322-ish email pattern — conservative (catches the common
// `user@example.com` form that flows through contact form bodies).
// Designed to be fast, not a complete RFC validator.
export const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

// UUID-v4 / token-like pattern.  Anchored on version nibble (4) and variant
// bits ([89ab]) to avoid matching git SHAs and other hex strings.
// Formerly named COMMENT_TOKEN_RE; kept for backwards-compat re-export.
export const COMMENT_TOKEN_RE =
  /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi;

// Bearer token pattern — matches `Bearer <token>` (case-insensitive on
// "Bearer") and replaces the token value with `[REDACTED]`.
// Must run BEFORE the key-name rule so the full `Authorization: Bearer <x>`
// is handled before `authorization` could partially match.
export const BEARER_RE = /\bBearer\s+([^\s"',;}\]]+)/gi;

// Secret/credential parameter by key name.
// Matches: key=value, "key":"value", "key": "value", key: value, etc.
// The \b word-boundary on the key prevents substrings (`real_estate` → `state`).
// Value stops at the first quote/whitespace/delimiter so innocent params
// (page=2, redirect_uri=...) aren't touched unless they follow a secret key.
//
// Key list (longest-stem-first for belt-and-suspenders, \b does real work):
//   access_token, refresh_token, id_token, client_secret, private_key,
//   api_key, apikey, sessionid, password, passwd, session, secret, token,
//   csrf, code, state, auth, pwd, key
//
// NOTE: `authorization` is intentionally absent — Bearer handles auth headers
// end-to-end.  Including `authorization` here would strip the word "Bearer"
// from the output after the Bearer rule already replaced the token value.
//
// ⚠️  Keep this list in sync with scrub.py (same keys, same order).
export const SECRET_KEY_RE =
  /\b(access_token|refresh_token|id_token|client_secret|private_key|api_key|apikey|sessionid|password|passwd|session|secret|token|csrf|code|state|auth|pwd|key)\b(\s*["']?\s*[:=]\s*["']?)([^"'&\s,;}\]]+)/gi;

/** Replace PII and secret patterns in a string with safe placeholders. */
export function scrubString(value: string): string {
  return value
    // 1. Bearer tokens — run first so the full token is removed before the
    //    key-name rule can partially match `authorization`.
    .replace(BEARER_RE, "Bearer [REDACTED]")
    // 2. Secret/credential params by key name (value redacted, key kept).
    .replace(SECRET_KEY_RE, "$1$2[REDACTED]")
    // 3. Email addresses.
    .replace(EMAIL_RE, "[REDACTED_EMAIL]")
    // 4. UUID-v4 / token-like patterns (comment_token etc.).
    .replace(COMMENT_TOKEN_RE, "[REDACTED_TOKEN]");
}

/**
 * Recursively scrub PII from an arbitrary value.
 *
 * Strings are scrubbed in place; arrays, plain-objects, and Record-like
 * containers are walked and their string members are scrubbed.  All other
 * types are returned unchanged.
 *
 * A `WeakSet` visitor guard prevents infinite recursion on circular object
 * graphs — any object already on the current walk stack is returned
 * unmodified.
 */
export function scrubAny(value: unknown, _visited?: WeakSet<object>): unknown {
  if (typeof value === "string") {
    return scrubString(value);
  }
  if (Array.isArray(value)) {
    const visited = _visited ?? new WeakSet<object>();
    if (visited.has(value)) return value;
    visited.add(value);
    return value.map((item) => scrubAny(item, visited));
  }
  if (value !== null && typeof value === "object") {
    const visited = _visited ?? new WeakSet<object>();
    if (visited.has(value)) return value;
    visited.add(value);
    const obj = value as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      obj[key] = scrubAny(obj[key], visited);
    }
    return obj;
  }
  return value;
}

/**
 * Sentry `beforeSend` hook — scrub PII from every event field.
 *
 * Visits the well-known locations where PII can land:
 *
 * - `event.message`
 * - `event.exception.values[*].value` (exception messages)
 * - `event.request.url` / `query_string`
 * - `event.breadcrumbs[*].message` + `.data`
 * - `event.extra` (deep walk)
 * - `event.tags`
 *
 * Mutates `event` in place and returns it. Returning `null` from
 * `beforeSend` would drop the event entirely — mutating and returning the
 * same object satisfies Sentry's contract. Nested containers (extra, tags,
 * breadcrumb data, query_string objects) are mutated in place by `scrubAny`.
 *
 * Unknown fields are left untouched to minimise blast radius.
 */
export function scrubEvent(event: ErrorEvent): ErrorEvent {
  // Top-level message
  if (typeof event.message === "string") {
    event.message = scrubString(event.message);
  }

  // Exception values (the human-readable message attached to each exception)
  if (event.exception?.values) {
    for (const exc of event.exception.values) {
      if (typeof exc.value === "string") {
        exc.value = scrubString(exc.value);
      }
    }
  }

  // Request metadata
  if (event.request) {
    if (typeof event.request.url === "string") {
      event.request.url = scrubString(event.request.url);
    }
    if (event.request.query_string !== undefined) {
      event.request.query_string = scrubAny(
        event.request.query_string,
      ) as typeof event.request.query_string;
    }
  }

  // Breadcrumbs — flat array in the JS SDK (contrast: Python SDK uses {values:[...]})
  if (event.breadcrumbs) {
    for (const crumb of event.breadcrumbs) {
      if (typeof crumb.message === "string") {
        crumb.message = scrubString(crumb.message);
      }
      if (crumb.data !== undefined) {
        crumb.data = scrubAny(crumb.data) as typeof crumb.data;
      }
    }
  }

  // Extra — arbitrary user-supplied context (deep walk)
  if (event.extra !== undefined) {
    event.extra = scrubAny(event.extra) as typeof event.extra;
  }

  // Tags — key/value pairs (values may be strings)
  if (event.tags !== undefined) {
    event.tags = scrubAny(event.tags) as typeof event.tags;
  }

  return event;
}
