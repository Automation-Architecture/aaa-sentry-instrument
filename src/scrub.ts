/**
 * Shared Sentry PII scrubber for AAA web apps.
 *
 * Lifted verbatim from `Automation-Architecture/aaa-client-dashboard`
 * `app/src/lib/sentry-scrub.ts` — this file IS the canonical source for
 * the package. If you need to change scrubbing logic, change it here and
 * keep the Python twin (`python/aaa_sentry_instrument/scrub.py`) in sync.
 *
 * Two categories of sensitive data flow through AAA services:
 *
 * 1. **Email addresses** — submitted via contact forms / API payloads.
 *    Pattern: RFC-5322-ish `user@host.tld`; scrubbed to `[EMAIL]`.
 *
 * 2. **comment_token** — UUID v4 stored in `project_client_comments` and
 *    passed as an edit/delete bearer credential on comment endpoints.
 *    Pattern: `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`; scrubbed to
 *    `[COMMENT_TOKEN]`.
 *
 * Regexes are kept byte-identical to the Python twin (`scrub.py`) so both
 * runtimes redact the same patterns.
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

// comment_token is a UUID v4 (see `project_client_comments.comment_token`).
// The bracket notation anchors the version nibble (4) and the variant bits
// ([89ab]) so we don't scrub unrelated hex strings like git SHAs.
export const COMMENT_TOKEN_RE =
  /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi;

/** Replace PII patterns in a string with safe placeholders. */
export function scrubString(value: string): string {
  return value
    .replace(EMAIL_RE, "[EMAIL]")
    .replace(COMMENT_TOKEN_RE, "[COMMENT_TOKEN]");
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
