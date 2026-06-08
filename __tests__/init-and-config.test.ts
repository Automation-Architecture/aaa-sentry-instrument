/**
 * Tests for v0.1.1 robustness improvements:
 *
 * 1. DSN whitespace trimming in initSentryClient / initSentryServer /
 *    initSentryEdge — surrounding whitespace must not fool the env-gate or
 *    reach Sentry.init.
 *
 * 2. withAaaSentry config-time validation — SENTRY_AUTH_TOKEN present but
 *    SENTRY_ORG / SENTRY_PROJECT absent must throw a clear error; all-set
 *    or token-absent must not throw.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Sentry mock — must supply every symbol loaded at module import time ──────
vi.mock("@sentry/nextjs", () => ({
  init: vi.fn(),
  withSentryConfig: vi.fn((_nextCfg: unknown, _sentryCfg: unknown) => _nextCfg),
  captureRequestError: vi.fn(),
  captureRouterTransitionStart: vi.fn(),
}));

import * as Sentry from "@sentry/nextjs";
import { initSentryClient, initSentryServer, initSentryEdge } from "../src/init.js";
import { withAaaSentry } from "../src/next-config.js";
import type { NextConfig } from "next";

// ── helpers ───────────────────────────────────────────────────────────────────

const REAL_DSN = "https://abc123@o0.ingest.sentry.io/123";
const DSN_WITH_WHITESPACE = `  ${REAL_DSN}  `;
const WHITESPACE_ONLY = "   ";

const mockInit = Sentry.init as ReturnType<typeof vi.fn>;

function capturedDsn(): string | undefined {
  return mockInit.mock.lastCall?.[0]?.dsn;
}
function capturedEnabled(): boolean | undefined {
  return mockInit.mock.lastCall?.[0]?.enabled;
}

// ── env snapshot / restore ────────────────────────────────────────────────────

let savedEnv: NodeJS.ProcessEnv;

beforeEach(() => {
  savedEnv = { ...process.env };
  mockInit.mockClear();
  // Clean all relevant env vars before each test
  delete process.env.NEXT_PUBLIC_SENTRY_DSN;
  delete process.env.SENTRY_DSN;
  delete process.env.SENTRY_AUTH_TOKEN;
  delete process.env.SENTRY_ORG;
  delete process.env.SENTRY_PROJECT;
});

afterEach(() => {
  // Restore original env
  for (const key of [
    "NEXT_PUBLIC_SENTRY_DSN",
    "SENTRY_DSN",
    "SENTRY_AUTH_TOKEN",
    "SENTRY_ORG",
    "SENTRY_PROJECT",
  ]) {
    if (key in savedEnv) {
      process.env[key] = savedEnv[key];
    } else {
      delete process.env[key];
    }
  }
});

// ── DSN trimming — initSentryClient ──────────────────────────────────────────

describe("initSentryClient — DSN whitespace trimming", () => {
  it("trims surrounding whitespace and passes cleaned DSN to Sentry.init", () => {
    process.env.NEXT_PUBLIC_SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryClient();
    expect(capturedDsn()).toBe(REAL_DSN);
  });

  it("sets enabled: true for a DSN that was whitespace-padded", () => {
    process.env.NEXT_PUBLIC_SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryClient();
    expect(capturedEnabled()).toBe(true);
  });

  it("treats a whitespace-only DSN as absent — enabled: false", () => {
    process.env.NEXT_PUBLIC_SENTRY_DSN = WHITESPACE_ONLY;
    initSentryClient();
    // A whitespace-only value trims to "" which is falsy → same as unset
    expect(capturedEnabled()).toBe(false);
  });

  it("passes undefined dsn when env var is absent", () => {
    initSentryClient();
    expect(capturedDsn()).toBeUndefined();
  });
});

// ── DSN trimming — initSentryServer ──────────────────────────────────────────

describe("initSentryServer — DSN whitespace trimming", () => {
  it("trims SENTRY_DSN and passes cleaned value to Sentry.init", () => {
    process.env.SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryServer();
    expect(capturedDsn()).toBe(REAL_DSN);
  });

  it("sets enabled: true for a whitespace-padded SENTRY_DSN", () => {
    process.env.SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryServer();
    expect(capturedEnabled()).toBe(true);
  });

  it("falls back to NEXT_PUBLIC_SENTRY_DSN (trimmed) when SENTRY_DSN is absent", () => {
    process.env.NEXT_PUBLIC_SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryServer();
    expect(capturedDsn()).toBe(REAL_DSN);
  });

  it("treats whitespace-only SENTRY_DSN as absent — enabled: false", () => {
    process.env.SENTRY_DSN = WHITESPACE_ONLY;
    initSentryServer();
    expect(capturedEnabled()).toBe(false);
  });
});

// ── DSN trimming — initSentryEdge ─────────────────────────────────────────────

describe("initSentryEdge — DSN whitespace trimming", () => {
  it("trims SENTRY_DSN and passes cleaned value to Sentry.init", () => {
    process.env.SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryEdge();
    expect(capturedDsn()).toBe(REAL_DSN);
  });

  it("sets enabled: true for a whitespace-padded SENTRY_DSN", () => {
    process.env.SENTRY_DSN = DSN_WITH_WHITESPACE;
    initSentryEdge();
    expect(capturedEnabled()).toBe(true);
  });

  it("treats whitespace-only SENTRY_DSN as absent — enabled: false", () => {
    process.env.SENTRY_DSN = WHITESPACE_ONLY;
    initSentryEdge();
    expect(capturedEnabled()).toBe(false);
  });
});

// ── withAaaSentry — source-map misconfiguration detection ────────────────────

const BARE_NEXT_CONFIG: NextConfig = {};

describe("withAaaSentry — source-map upload misconfiguration", () => {
  it("throws when SENTRY_AUTH_TOKEN is set but SENTRY_ORG is missing", () => {
    process.env.SENTRY_AUTH_TOKEN = "sntryu_abc123";
    process.env.SENTRY_PROJECT = "my-project";
    // SENTRY_ORG intentionally absent
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).toThrow(/SENTRY_AUTH_TOKEN/);
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).toThrow(/SENTRY_ORG/);
  });

  it("throws when SENTRY_AUTH_TOKEN is set but SENTRY_PROJECT is missing", () => {
    process.env.SENTRY_AUTH_TOKEN = "sntryu_abc123";
    process.env.SENTRY_ORG = "my-org";
    // SENTRY_PROJECT intentionally absent
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).toThrow(/SENTRY_AUTH_TOKEN/);
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).toThrow(/SENTRY_PROJECT/);
  });

  it("throws when SENTRY_AUTH_TOKEN is set but both ORG and PROJECT are missing", () => {
    process.env.SENTRY_AUTH_TOKEN = "sntryu_abc123";
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).toThrow(
      /SENTRY_AUTH_TOKEN is set but SENTRY_ORG\/SENTRY_PROJECT are missing/
    );
  });

  it("does NOT throw when all three are set", () => {
    process.env.SENTRY_AUTH_TOKEN = "sntryu_abc123";
    process.env.SENTRY_ORG = "my-org";
    process.env.SENTRY_PROJECT = "my-project";
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).not.toThrow();
  });

  it("does NOT throw when SENTRY_AUTH_TOKEN is absent (local dev)", () => {
    // No auth token — source-map upload disabled, no validation required
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).not.toThrow();
  });

  it("does NOT throw when SENTRY_AUTH_TOKEN is absent even if ORG/PROJECT are also absent", () => {
    expect(() => withAaaSentry(BARE_NEXT_CONFIG)).not.toThrow();
  });
});
