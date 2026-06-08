/**
 * House-default Sentry initialization helpers for AAA Next.js apps.
 *
 * Each helper wraps `Sentry.init` with the policies agreed across all AAA
 * projects:
 *
 * - **env-gated**: no-op when the relevant DSN env var is absent (safe for
 *   local dev / CI that has not wired Sentry yet).
 * - **sampling**: 10% in production, 100% in development.
 * - **replay OFF** (privacy-conservative default).
 * - **PII scrubbing** via `scrubEvent` (emails + comment_token UUIDs).
 * - **environment** derived from `VERCEL_ENV` / `NEXT_PUBLIC_VERCEL_ENV` /
 *   `NODE_ENV` (works on Vercel and any plain Node host).
 * - **release** uses `VERCEL_GIT_COMMIT_SHA` on server/edge; omitted on the
 *   client (not exposed to the browser by default — `withSentryConfig`
 *   injects it at build time).
 *
 * Re-exports `onRouterTransitionStart` and `onRequestError` so consuming
 * apps don't need to import `@sentry/nextjs` directly.
 *
 * @module
 */

import * as Sentry from "@sentry/nextjs";
import { scrubEvent } from "./scrub.js";

// ── shared DSN helpers ─────────────────────────────────────────────────────

function clientDsn(): string | undefined {
  return process.env.NEXT_PUBLIC_SENTRY_DSN?.trim() || undefined;
}

function serverDsn(): string | undefined {
  return (
    process.env.SENTRY_DSN?.trim() ||
    process.env.NEXT_PUBLIC_SENTRY_DSN?.trim() ||
    undefined
  );
}

function sampleRate(): number {
  return process.env.NODE_ENV === "development" ? 1.0 : 0.1;
}

// ── public init functions ──────────────────────────────────────────────────

/**
 * Initialise Sentry for the browser (client) runtime.
 *
 * Call from `instrumentation-client.ts` (Next.js 15+) or
 * `sentry.client.config.ts` (older Next.js).
 */
export function initSentryClient(): void {
  Sentry.init({
    dsn: clientDsn(),
    enabled: Boolean(clientDsn()),

    tracesSampleRate: sampleRate(),

    // Session replay OFF — privacy-conservative default.
    replaysSessionSampleRate: 0,
    replaysOnErrorSampleRate: 0,

    // Environment for filtering in the Sentry dashboard.
    // NEXT_PUBLIC_VERCEL_ENV is available to the browser on Vercel.
    environment:
      process.env.NEXT_PUBLIC_VERCEL_ENV || process.env.NODE_ENV,

    // release omitted — withSentryConfig injects it from
    // VERCEL_GIT_COMMIT_SHA at build time into the client bundle.

    beforeSend(event) {
      return scrubEvent(event);
    },
  });
}

/**
 * Initialise Sentry for the Node.js server runtime.
 *
 * Call from `instrumentation.ts#register()` when
 * `process.env.NEXT_RUNTIME === "nodejs"`.
 */
export function initSentryServer(): void {
  Sentry.init({
    dsn: serverDsn(),
    enabled: Boolean(serverDsn()),

    tracesSampleRate: sampleRate(),

    environment: process.env.VERCEL_ENV || process.env.NODE_ENV,
    release: process.env.VERCEL_GIT_COMMIT_SHA,

    beforeSend(event) {
      return scrubEvent(event);
    },
  });
}

/**
 * Initialise Sentry for the Vercel edge runtime.
 *
 * Call from `instrumentation.ts#register()` when
 * `process.env.NEXT_RUNTIME === "edge"`.
 */
export function initSentryEdge(): void {
  Sentry.init({
    dsn: serverDsn(),
    enabled: Boolean(serverDsn()),

    tracesSampleRate: sampleRate(),

    environment: process.env.VERCEL_ENV || process.env.NODE_ENV,
    release: process.env.VERCEL_GIT_COMMIT_SHA,

    beforeSend(event) {
      return scrubEvent(event);
    },
  });
}

// ── pass-through re-exports for instrumentation files ─────────────────────

/**
 * Re-exported from `@sentry/nextjs` so apps can use this package as their
 * sole Sentry import.
 *
 * In `instrumentation-client.ts`:
 * ```ts
 * export { onRouterTransitionStart } from "aaa-sentry-instrument";
 * ```
 *
 * `captureRouterTransitionStart` is a browser-only API not present in the
 * main @sentry/nextjs TypeScript export map. We access it via a cast to
 * avoid a build error — it is always present at runtime in the browser
 * bundle. Server/edge runtimes never call this export.
 */
export const onRouterTransitionStart = (
  Sentry as typeof Sentry & {
    captureRouterTransitionStart: (href: string, navigationType: string) => void;
  }
).captureRouterTransitionStart;

/**
 * Re-exported from `@sentry/nextjs` so apps can use this package as their
 * sole Sentry import.
 *
 * In `instrumentation.ts`:
 * ```ts
 * export { onRequestError } from "aaa-sentry-instrument";
 * ```
 */
export const onRequestError = Sentry.captureRequestError;
