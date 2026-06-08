/**
 * Tests for the JS Sentry PII scrubber (`src/scrub.ts`).
 *
 * Ported from `Automation-Architecture/aaa-client-dashboard`
 * `backend/tests/test_sentry_scrubber.py` and extended with JS-specific
 * cases (circular-ref safety, breadcrumb array shape).
 *
 * Covers:
 * - Email addresses (replaced with `[EMAIL]`)
 * - comment_token UUIDs (replaced with `[COMMENT_TOKEN]`)
 * - Deep nesting (extra, tags, nested objects)
 * - Circular reference safety (scrubAny with WeakSet guard via object identity)
 * - All well-known event fields: message, exception, request, breadcrumbs,
 *   extra, tags
 */

import { describe, it, expect } from "vitest";
import {
  scrubString,
  scrubAny,
  scrubEvent,
  EMAIL_RE,
  COMMENT_TOKEN_RE,
} from "../src/scrub.js";
import type { ErrorEvent } from "@sentry/nextjs";

// ── fixtures ───────────────────────────────────────────────────────────────

const SAMPLE_EMAIL = "client@acme-corp.io";
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
});

// ── scrubString ────────────────────────────────────────────────────────────

describe("scrubString", () => {
  it("redacts an email address", () => {
    expect(scrubString(`Contact from ${SAMPLE_EMAIL}`)).toBe(
      "Contact from [EMAIL]"
    );
  });

  it("redacts a comment_token UUID", () => {
    expect(scrubString(`token=${SAMPLE_TOKEN}`)).toBe("token=[COMMENT_TOKEN]");
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
    expect(scrubString(nonV4)).toBe(nonV4);
  });

  it("redacts multiple occurrences of different PII in one string", () => {
    const value = `${SAMPLE_EMAIL} sent comment ${SAMPLE_TOKEN}`;
    const scrubbed = scrubString(value);
    expect(scrubbed).not.toContain(SAMPLE_EMAIL);
    expect(scrubbed).not.toContain(SAMPLE_TOKEN);
    expect(scrubbed).toContain("[EMAIL]");
    expect(scrubbed).toContain("[COMMENT_TOKEN]");
  });
});

// ── scrubAny — deep nesting ────────────────────────────────────────────────

describe("scrubAny", () => {
  it("scrubs string values", () => {
    expect(scrubAny(SAMPLE_EMAIL)).toBe("[EMAIL]");
  });

  it("leaves non-string primitives unchanged", () => {
    expect(scrubAny(42)).toBe(42);
    expect(scrubAny(true)).toBe(true);
    expect(scrubAny(null)).toBeNull();
  });

  it("scrubs strings inside arrays", () => {
    const result = scrubAny([SAMPLE_EMAIL, "safe"]) as string[];
    expect(result[0]).toBe("[EMAIL]");
    expect(result[1]).toBe("safe");
  });

  it("scrubs strings inside nested objects", () => {
    const result = scrubAny({
      level1: {
        level2: { email: SAMPLE_EMAIL, token: SAMPLE_TOKEN, safe: "keep" },
      },
    }) as Record<string, Record<string, Record<string, string>>>;
    expect(result.level1.level2.email).toBe("[EMAIL]");
    expect(result.level1.level2.token).toBe("[COMMENT_TOKEN]");
    expect(result.level1.level2.safe).toBe("keep");
  });

  it("handles true circular references without throwing or infinite-looping", () => {
    // scrubAny uses a WeakSet visited guard — a real cycle must not stack-overflow.
    const obj: Record<string, unknown> = { email: SAMPLE_EMAIL };
    obj.self = obj; // genuine cycle
    expect(() => scrubAny(obj)).not.toThrow();
    // The email in the top-level string field should still be scrubbed.
    const result = scrubAny({ email: SAMPLE_EMAIL }) as Record<string, string>;
    expect(result.email).toBe("[EMAIL]");
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
    expect(rendered).toContain("[EMAIL]");
    expect(rendered).toContain("[COMMENT_TOKEN]");

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
    expect(scrubbed.message).toContain("[EMAIL]");
    expect(scrubbed.message).toContain("[COMMENT_TOKEN]");
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
    expect(nested.contact_email).toBe("[EMAIL]");
    expect(nested.auth_token).toBe("[COMMENT_TOKEN]");
  });
});
