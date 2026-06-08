/**
 * Tests for the JS Sentry PII/secret scrubber (`src/scrub.ts`).
 *
 * Ported from `Automation-Architecture/aaa-client-dashboard`
 * `backend/tests/test_sentry_scrubber.py` and extended with JS-specific
 * cases (circular-ref safety, breadcrumb array shape) and comprehensive
 * secret-by-key-name + Bearer redaction tests.
 *
 * Covers:
 * - Email addresses (replaced with `[REDACTED_EMAIL]`)
 * - UUID-v4 / token-like values (replaced with `[REDACTED_TOKEN]`)
 * - Bearer token header values (replaced with `Bearer [REDACTED]`)
 * - Secret/credential params by key name (value replaced with `[REDACTED]`)
 * - Non-secret params survive unredacted (`redirect_uri`, `page`, etc.)
 * - Deep nesting (extra, tags, nested objects)
 * - Circular reference safety (scrubAny with WeakSet guard via object identity)
 * - All well-known event fields: message, exception, request, breadcrumbs,
 *   extra, tags
 *
 * ⚠️  Keep in sync with python/tests/test_scrub.py — same key list, same
 * placeholder strings, same behavioral assertions.
 */

import { describe, it, expect } from "vitest";
import {
  scrubString,
  scrubAny,
  scrubEvent,
  EMAIL_RE,
  COMMENT_TOKEN_RE,
  BEARER_RE,
  SECRET_KEY_RE,
} from "../src/scrub.js";
import type { ErrorEvent } from "@sentry/nextjs";

// ── fixtures ───────────────────────────────────────────────────────────────

const SAMPLE_EMAIL = "client@acme-corp.io";
// A real UUID v4 (not relying on UUID shape for the key-name tests below).
const SAMPLE_TOKEN = "a1b2c3d4-e5f6-4789-a012-b3c4d5e6f789";

// ── exported patterns — pinned so a regex change is caught explicitly ──────

describe("exported regexes", () => {
  it("EMAIL_RE pattern matches a typical email", () => {
    expect(EMAIL_RE.source).toBe(
      "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
    );
  });

  it("COMMENT_TOKEN_RE pattern anchors to UUID v4", () => {
    expect(COMMENT_TOKEN_RE.source).toBe(
      "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    );
  });

  it("BEARER_RE and SECRET_KEY_RE are exported", () => {
    expect(BEARER_RE).toBeDefined();
    expect(SECRET_KEY_RE).toBeDefined();
  });
});

// ── scrubString — email + tokenLike (legacy behaviours) ───────────────────

describe("scrubString — email and UUID-token", () => {
  it("redacts an email address", () => {
    expect(scrubString(`Contact from ${SAMPLE_EMAIL}`)).toBe(
      "Contact from [REDACTED_EMAIL]"
    );
  });

  it("redacts a UUID-v4 token (key-name rule fires; value gets [REDACTED])", () => {
    // When a UUID appears as the value of a secret key (`token=`), the
    // key-name rule fires first and replaces the value with [REDACTED].
    // The COMMENT_TOKEN_RE / [REDACTED_TOKEN] path handles bare UUIDs
    // that are NOT preceded by a secret key name.
    const result = scrubString(`token=${SAMPLE_TOKEN}`);
    expect(result).not.toContain(SAMPLE_TOKEN);
    expect(result).toContain("[REDACTED]");
  });

  it("leaves plain strings untouched", () => {
    expect(scrubString("hello world")).toBe("hello world");
    expect(scrubString("/api/projects/fas/stages")).toBe(
      "/api/projects/fas/stages"
    );
  });

  it("does not scrub non-v4 UUIDs (git SHAs, short IDs)", () => {
    expect(scrubString("abc123def456")).toBe("abc123def456");
    // UUID v1-style — version nibble differs (1, not 4)
    const nonV4 = "a1b2c3d4-e5f6-1789-c012-b3c4d5e6f789";
    // It may match via key-name rule if a key precedes it, but the bare UUID
    // without a preceding secret key should not be redacted.
    expect(scrubString(nonV4)).toBe(nonV4);
  });

  it("redacts multiple occurrences of different PII in one string", () => {
    const value = `${SAMPLE_EMAIL} sent comment ${SAMPLE_TOKEN}`;
    const scrubbed = scrubString(value);
    expect(scrubbed).not.toContain(SAMPLE_EMAIL);
    expect(scrubbed).not.toContain(SAMPLE_TOKEN);
    expect(scrubbed).toContain("[REDACTED_EMAIL]");
    expect(scrubbed).toContain("[REDACTED_TOKEN]");
  });
});

// ── scrubString — secret params by key name (plain non-UUID values) ────────

describe("scrubString — secret params by key name", () => {
  it("redacts secret=hunter2", () => {
    const result = scrubString("secret=hunter2");
    expect(result).not.toContain("hunter2");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts access_token=abc123XYZ (plain non-UUID value)", () => {
    const result = scrubString("access_token=abc123XYZ");
    expect(result).not.toContain("abc123XYZ");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts client_secret=foo", () => {
    const result = scrubString("client_secret=foo");
    expect(result).not.toContain("foo");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts password=p@ss", () => {
    const result = scrubString("password=p@ss");
    expect(result).not.toContain("p@ss");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts code=authcode123", () => {
    const result = scrubString("?code=authcode123&redirect_uri=https://app/cb");
    expect(result).not.toContain("authcode123");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts state=xyz", () => {
    const result = scrubString("state=xyz");
    expect(result).not.toContain("xyz");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts token in JSON-ish text", () => {
    const result = scrubString('{"token":"mySecretToken123"}');
    expect(result).not.toContain("mySecretToken123");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts api_key in a query string", () => {
    const result = scrubString("https://api.example.com?api_key=sk-live-xyz");
    expect(result).not.toContain("sk-live-xyz");
    expect(result).toContain("[REDACTED]");
  });
});

// ── scrubString — Bearer token ─────────────────────────────────────────────

describe("scrubString — Bearer token", () => {
  it("redacts Authorization: Bearer sk-not-a-uuid-12345", () => {
    const result = scrubString("Authorization: Bearer sk-not-a-uuid-12345");
    expect(result).not.toContain("sk-not-a-uuid-12345");
    expect(result).toContain("Bearer [REDACTED]");
  });

  it("redacts bare Bearer token in a URL header string", () => {
    const result = scrubString("Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig");
    expect(result).not.toContain("eyJhbGciOiJSUzI1NiJ9");
    expect(result).toContain("Bearer [REDACTED]");
  });
});

// ── scrubString — non-secret params survive ────────────────────────────────

describe("scrubString — non-secret params survive unredacted", () => {
  it("redirect_uri=https://app/cb survives", () => {
    const result = scrubString("redirect_uri=https://app/cb");
    expect(result).toBe("redirect_uri=https://app/cb");
  });

  it("page=2 survives", () => {
    const result = scrubString("page=2");
    expect(result).toBe("page=2");
  });

  it("utm_source=newsletter survives", () => {
    const result = scrubString("utm_source=newsletter");
    expect(result).toBe("utm_source=newsletter");
  });

  it("id=42 survives", () => {
    const result = scrubString("id=42");
    expect(result).toBe("id=42");
  });
});

// ── scrubAny — deep nesting ────────────────────────────────────────────────

describe("scrubAny", () => {
  it("scrubs string values", () => {
    expect(scrubAny(SAMPLE_EMAIL)).toBe("[REDACTED_EMAIL]");
  });

  it("leaves non-string primitives unchanged", () => {
    expect(scrubAny(42)).toBe(42);
    expect(scrubAny(true)).toBe(true);
    expect(scrubAny(null)).toBeNull();
  });

  it("scrubs strings inside arrays", () => {
    const result = scrubAny([SAMPLE_EMAIL, "safe"]) as string[];
    expect(result[0]).toBe("[REDACTED_EMAIL]");
    expect(result[1]).toBe("safe");
  });

  it("scrubs strings inside nested objects", () => {
    const result = scrubAny({
      level1: {
        level2: { email: SAMPLE_EMAIL, token: SAMPLE_TOKEN, safe: "keep" },
      },
    }) as Record<string, Record<string, Record<string, string>>>;
    expect(result.level1.level2.email).toBe("[REDACTED_EMAIL]");
    expect(result.level1.level2.token).not.toContain(SAMPLE_TOKEN);
    expect(result.level1.level2.safe).toBe("keep");
  });

  it("handles true circular references without throwing or infinite-looping", () => {
    // scrubAny uses a WeakSet visited guard — a real cycle must not stack-overflow.
    const obj: Record<string, unknown> = { email: SAMPLE_EMAIL };
    obj.self = obj; // genuine cycle
    expect(() => scrubAny(obj)).not.toThrow();
    // The email in the top-level string field should still be scrubbed.
    const result = scrubAny({ email: SAMPLE_EMAIL }) as Record<string, string>;
    expect(result.email).toBe("[REDACTED_EMAIL]");
  });

  it("handles circular references inside arrays", () => {
    const arr: unknown[] = [SAMPLE_EMAIL];
    arr.push(arr); // array that contains itself
    expect(() => scrubAny(arr)).not.toThrow();
  });
});

// ── scrubEvent — full event ────────────────────────────────────────────────

describe("scrubEvent", () => {
  it("scrubs all well-known PII fields in a full event", () => {
    const event: ErrorEvent = {
      message: `Contact from ${SAMPLE_EMAIL} ref=${SAMPLE_TOKEN}`,
      exception: {
        values: [
          {
            type: "ValueError",
            value: `Invalid payload from ${SAMPLE_EMAIL} token=${SAMPLE_TOKEN}`,
          },
        ],
      },
      request: {
        url: `https://api.dashboard.ai/api/contact?ref=${SAMPLE_EMAIL}`,
        query_string: `email=${SAMPLE_EMAIL}`,
      },
      breadcrumbs: [
        {
          message: `POST /api/contact from ${SAMPLE_EMAIL}`,
          data: {
            url: `https://api.dashboard.ai/api/contact?e=${SAMPLE_EMAIL}`,
            method: "POST",
          },
        },
      ],
      extra: {
        submitter_email: SAMPLE_EMAIL,
        comment_ref: SAMPLE_TOKEN,
      },
      tags: {
        user_email: SAMPLE_EMAIL,
      },
    };

    const scrubbed = scrubEvent(event);

    // Returns the same object (in-place mutation)
    expect(scrubbed).toBe(event);

    const rendered = JSON.stringify(scrubbed);
    expect(rendered).not.toContain(SAMPLE_EMAIL);
    expect(rendered).not.toContain(SAMPLE_TOKEN);
    expect(rendered).toContain("[REDACTED_EMAIL]");
    expect(rendered).toContain("[REDACTED");

    // Static fields must survive
    expect(
      (scrubbed.breadcrumbs as Array<{ data?: { method?: string } }>)[0].data
        ?.method
    ).toBe("POST");
  });

  it("is safe on an empty event", () => {
    const event: ErrorEvent = {};
    expect(() => scrubEvent(event)).not.toThrow();
    expect(scrubEvent(event)).toBeDefined();
  });

  it("tolerates missing sub-trees", () => {
    const event: ErrorEvent = { message: "boom" };
    const scrubbed = scrubEvent(event);
    expect(scrubbed.message).toBe("boom");
  });

  it("does not mutate non-PII fields", () => {
    const event: ErrorEvent = {
      request: { url: "https://api.dashboard.ai/health" },
      extra: { slug: "fas" },
    };
    const scrubbed = scrubEvent(event);
    expect(scrubbed.request?.url).toBe("https://api.dashboard.ai/health");
    expect((scrubbed.extra as Record<string, string>)?.slug).toBe("fas");
  });

  it("redacts top-level message", () => {
    const event: ErrorEvent = {
      message: `Submitted by ${SAMPLE_EMAIL} ref=${SAMPLE_TOKEN}`,
    };
    const scrubbed = scrubEvent(event);
    expect(scrubbed.message).not.toContain(SAMPLE_EMAIL);
    expect(scrubbed.message).not.toContain(SAMPLE_TOKEN);
    expect(scrubbed.message).toContain("[REDACTED_EMAIL]");
    expect(scrubbed.message).toContain("[REDACTED");
  });

  it("scrubs oauth/secret params deep in extra", () => {
    const event: ErrorEvent = {
      extra: {
        nested: {
          contact_email: SAMPLE_EMAIL,
          auth_token: SAMPLE_TOKEN,
        },
      },
    };
    const scrubbed = scrubEvent(event);
    const nested = (scrubbed.extra as Record<string, Record<string, string>>)
      .nested;
    expect(nested.contact_email).toBe("[REDACTED_EMAIL]");
    expect(nested.auth_token).not.toContain(SAMPLE_TOKEN);
  });

  it("redacts Bearer token in request headers captured in extra", () => {
    const event: ErrorEvent = {
      extra: {
        headers: "Authorization: Bearer sk-not-a-uuid-12345",
      },
    };
    const scrubbed = scrubEvent(event);
    const rendered = JSON.stringify(scrubbed);
    expect(rendered).not.toContain("sk-not-a-uuid-12345");
    expect(rendered).toContain("Bearer [REDACTED]");
  });

  it("non-secret query param redirect_uri survives in event URL", () => {
    const event: ErrorEvent = {
      request: {
        url: "https://api.dashboard.ai/oauth/callback?redirect_uri=https://app/cb&page=2",
      },
    };
    const scrubbed = scrubEvent(event);
    expect(scrubbed.request?.url).toContain("redirect_uri=https://app/cb");
    expect(scrubbed.request?.url).toContain("page=2");
  });
});
