/**
 * aaa-sentry-instrument — public API
 *
 * Install from GitHub:
 *   npm install github:Automation-Architecture/aaa-sentry-instrument
 *
 * Usage:
 *   import { initSentryClient, initSentryServer, initSentryEdge,
 *            withAaaSentry, scrubEvent,
 *            onRouterTransitionStart, onRequestError }
 *     from "aaa-sentry-instrument";
 */

// Scrubber — the heart of the package.  JS and Python twins must stay in sync.
export { scrubEvent, scrubString, scrubAny, EMAIL_RE, COMMENT_TOKEN_RE } from "./scrub.js";

// Sentry init helpers.
export {
  initSentryClient,
  initSentryServer,
  initSentryEdge,
  onRouterTransitionStart,
  onRequestError,
} from "./init.js";

// Next.js config wrapper.
export { withAaaSentry } from "./next-config.js";
