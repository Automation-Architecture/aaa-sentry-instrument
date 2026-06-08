#!/usr/bin/env node
/**
 * aaa-sentry-instrument init
 *
 * Scaffolds the four thin Sentry instrumentation files that every AAA
 * Next.js app needs. Each file is a one-liner that delegates to this
 * package. Idempotent — skips files that already exist.
 *
 * Usage:
 *   npx aaa-sentry-instrument init
 *   # or after install:
 *   ./node_modules/.bin/aaa-sentry-instrument init
 */

import { existsSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ── detect app layout (app/ or src/) ──────────────────────────────────────

const cwd = process.cwd();
const hasSrc = existsSync(join(cwd, "src"));
const hasApp = existsSync(join(cwd, "app"));

// Next.js 15 convention: instrumentation files live alongside pages,
// i.e. in src/ if that layout is used, otherwise at root.
let srcDir;
if (hasSrc) {
  srcDir = join(cwd, "src");
} else if (hasApp) {
  // app/ directory layout without a separate src/ — put files in app/
  srcDir = join(cwd, "app");
} else {
  // Fallback: root (will be placed at the project root)
  srcDir = cwd;
}

console.log(`\naaa-sentry-instrument init`);
console.log(`Detected layout: ${srcDir}\n`);

// ── file definitions ───────────────────────────────────────────────────────

const files = [
  {
    name: "sentry.server.config.ts",
    content: `import { initSentryServer } from "aaa-sentry-instrument";
initSentryServer();
`,
  },
  {
    name: "sentry.edge.config.ts",
    content: `import { initSentryEdge } from "aaa-sentry-instrument";
initSentryEdge();
`,
  },
  {
    name: "instrumentation-client.ts",
    content: `import { initSentryClient, onRouterTransitionStart } from "aaa-sentry-instrument";
initSentryClient();
export { onRouterTransitionStart };
`,
  },
  {
    name: "instrumentation.ts",
    content: `export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");
  }
  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }
}
export { onRequestError } from "aaa-sentry-instrument";
`,
  },
];

// ── scaffold ───────────────────────────────────────────────────────────────

mkdirSync(srcDir, { recursive: true });

let created = 0;
let skipped = 0;

for (const { name, content } of files) {
  const dest = join(srcDir, name);
  if (existsSync(dest)) {
    console.log(`  SKIP   ${dest}  (already exists)`);
    skipped++;
  } else {
    writeFileSync(dest, content, "utf8");
    console.log(`  CREATE ${dest}`);
    created++;
  }
}

// ── print next steps ───────────────────────────────────────────────────────

console.log(`
  ${created} file(s) created, ${skipped} skipped.

Next steps
──────────

1. Wrap your Next.js config in next.config.ts:

   import type { NextConfig } from "next";
   import { withAaaSentry } from "aaa-sentry-instrument";

   const nextConfig: NextConfig = { /* your config */ };
   export default withAaaSentry(nextConfig);

2. Set the following env vars in .env.local (dev) and your Vercel project (prod):

   NEXT_PUBLIC_SENTRY_DSN=https://...@sentry.io/...   # client + server/edge
   SENTRY_DSN=https://...@sentry.io/...               # server/edge only (optional override)
   SENTRY_ORG=your-sentry-org-slug
   SENTRY_PROJECT=your-sentry-project-slug
   SENTRY_AUTH_TOKEN=<from Sentry Settings → API Keys>

   NEXT_PUBLIC_SENTRY_DSN and SENTRY_AUTH_TOKEN must also be set in Vercel
   for source-map upload to work during production builds.

3. Ensure instrumentation is enabled in next.config.ts:

   const nextConfig: NextConfig = {
     experimental: { instrumentationHook: true },   // only needed for Next.js < 15.3
   };

Done. Run \`npm run build\` to verify the Sentry plugin integrates cleanly.
`);
