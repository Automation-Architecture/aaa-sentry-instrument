/**
 * `withAaaSentry(nextConfig)` — wraps `withSentryConfig` with AAA house
 * defaults for the Next.js webpack plugin.
 *
 * Consumers add a single call to their `next.config.ts`:
 *
 * ```ts
 * import { withAaaSentry } from "aaa-sentry-instrument/next-config";
 * // or from the root:
 * import { withAaaSentry } from "aaa-sentry-instrument";
 *
 * export default withAaaSentry(nextConfig);
 * ```
 *
 * Per-project configuration comes from env vars:
 *
 * | Env var            | Purpose                                      |
 * |--------------------|----------------------------------------------|
 * | `SENTRY_ORG`       | Sentry organisation slug (source-map upload) |
 * | `SENTRY_PROJECT`   | Sentry project slug (source-map upload)      |
 * | `SENTRY_AUTH_TOKEN`| Disables source-map upload when absent       |
 * | `CI`               | Enables verbose build logs when set          |
 *
 * @module
 */

import { withSentryConfig } from "@sentry/nextjs";
import type { NextConfig } from "next";

/**
 * Wrap a Next.js config with Sentry's webpack plugin using AAA house
 * defaults.
 *
 * @param nextConfig - The base `NextConfig` object from `next.config.ts`.
 * @returns A Sentry-wrapped `NextConfig`.
 */
export function withAaaSentry(nextConfig: NextConfig): NextConfig {
  return withSentryConfig(nextConfig, {
    // Sentry org + project come from env vars so this wrapper is
    // project-agnostic and works across all AAA apps.
    org: process.env.SENTRY_ORG,
    project: process.env.SENTRY_PROJECT,

    // Quieter build logs unless running in CI.
    silent: !process.env.CI,

    // Route Sentry's ingest through our own origin to avoid ad-blockers.
    tunnelRoute: "/monitoring",

    // Upload source maps only when an auth token is present (CI / Vercel).
    sourcemaps: {
      disable: !process.env.SENTRY_AUTH_TOKEN,
    },

    // Prevent source maps from being served publicly.
    widenClientFileUpload: true,
  });
}
