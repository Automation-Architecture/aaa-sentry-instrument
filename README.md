# aaa-sentry-instrument

Reusable Sentry instrumentation for AAA web apps. Two packages, one repo:

| Stack | Package |
|-------|---------|
| Next.js (TypeScript) | `aaa-sentry-instrument` — root of this repo |
| FastAPI (Python) | `aaa-sentry-instrument` — `python/` subdirectory |

Both include a PII scrubber that redacts email addresses and `comment_token`
UUIDs from every event before it leaves the process. The JS and Python scrubbers
use byte-identical regex patterns.

---

## JavaScript / TypeScript (Next.js)

### Install

```sh
npm install "git+https://github.com/Automation-Architecture/aaa-sentry-instrument.git#v0.1.2"
```

The package builds during install via `prepare: tsc`. Peer dependency:
`@sentry/nextjs >= 8`.

> **Why `git+https` instead of the `github:` shorthand?**
> The `github:` shorthand resolves to a `git+ssh://` URL in the lockfile.
> SSH authentication fails in keyless CI environments (Vercel, GitHub Actions, Railway).
> The explicit `git+https` form with a pinned tag is reproducible and works in every
> build environment without any SSH key configuration.

> **Repo is public — no auth token needed in CI.**

> **pnpm apps:** the package must be listed under `allowBuilds` in `pnpm-workspace.yaml`;
> otherwise pnpm skips the `prepare`/`tsc` build step and imports fail with no obvious error:
> ```yaml
> # pnpm-workspace.yaml
> allowBuilds:
>   - aaa-sentry-instrument
> ```

> **Versioning:** pin to a tag (e.g. `#v0.1.2`). To upgrade, publish a new tag and
> bump the `#<tag>` reference in `package.json`.

### Scaffold (recommended)

```sh
npx aaa-sentry-instrument init
```

This creates four thin files in your `src/` (or `app/`) directory and prints
the `next.config.ts` snippet and required env vars.

### Manual wiring

**`src/sentry.server.config.ts`**
```ts
import { initSentryServer } from "aaa-sentry-instrument";
initSentryServer();
```

**`src/sentry.edge.config.ts`**
```ts
import { initSentryEdge } from "aaa-sentry-instrument";
initSentryEdge();
```

**`src/instrumentation-client.ts`**
```ts
import { initSentryClient, onRouterTransitionStart } from "aaa-sentry-instrument";
initSentryClient();
export { onRouterTransitionStart };
```

**`src/instrumentation.ts`**
```ts
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");
  }
  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }
}
export { onRequestError } from "aaa-sentry-instrument";
```

**`next.config.ts`**
```ts
import type { NextConfig } from "next";
import { withAaaSentry } from "aaa-sentry-instrument";

const nextConfig: NextConfig = { /* your config */ };
export default withAaaSentry(nextConfig);
```

### Environment variables

| Variable | Runtime | Purpose |
|----------|---------|---------|
| `NEXT_PUBLIC_SENTRY_DSN` | client + server/edge | DSN for all runtimes |
| `SENTRY_DSN` | server/edge only | Override DSN (optional) |
| `SENTRY_ORG` | build | Sentry org slug for source-map upload |
| `SENTRY_PROJECT` | build | Sentry project slug for source-map upload |
| `SENTRY_AUTH_TOKEN` | build | Enables source-map upload when set |

All init functions are silent no-ops when the relevant DSN var is unset.

### House defaults baked in

| Setting | Value |
|---------|-------|
| `tracesSampleRate` | `0.1` (prod) / `1.0` (dev) |
| Session replay | OFF |
| `beforeSend` | `scrubEvent` — redacts emails + UUID v4 comment tokens |
| `tunnelRoute` | `/monitoring` |
| Source maps | uploaded only when `SENTRY_AUTH_TOKEN` is set |

### Public API

```ts
// Scrubber
export { scrubEvent, scrubString, scrubAny, EMAIL_RE, COMMENT_TOKEN_RE }

// Init helpers
export { initSentryClient, initSentryServer, initSentryEdge }

// Pass-throughs from @sentry/nextjs
export { onRouterTransitionStart, onRequestError }

// Next.js config wrapper
export { withAaaSentry }
```

---

## Python (FastAPI)

### Install

```sh
pip install "aaa-sentry-instrument @ git+https://github.com/Automation-Architecture/aaa-sentry-instrument.git@v0.1.2#subdirectory=python"
```

> **Repo is public — no auth token needed in CI.**
>
> **Versioning:** pin to a tag (e.g. `@v0.1.2`). To upgrade, publish a new tag and
> bump the `@<tag>` reference in your `requirements.txt` / `pyproject.toml`.

### Usage

```python
from aaa_sentry_instrument import init_sentry

# Call before constructing the FastAPI app so integrations hook at import time.
init_sentry()

app = FastAPI(...)
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `SENTRY_DSN` | Required. No-op when absent. |
| `RAILWAY_ENVIRONMENT` | Defaults to `"production"` when absent. |
| `RAILWAY_GIT_COMMIT_SHA` | Release tag. Omit locally. |

### House defaults baked in

| Setting | Value |
|---------|-------|
| `traces_sample_rate` | `0.1` |
| `send_default_pii` | `False` |
| `before_send` | `scrub_pii` — redacts emails + UUID v4 comment tokens |
| Integrations | `FastApiIntegration`, `AsyncioIntegration` |

### Overrides

```python
init_sentry(
    traces_sample_rate=1.0,            # 100% for staging
    extra_integrations=[LoggingIntegration(...)],
)
```

### Public API

```python
from aaa_sentry_instrument import (
    init_sentry,       # main entry point
    scrub_pii,         # Sentry before_send hook
    _scrub_string,     # unit-testable string scrubber
    _scrub_any,        # recursive scrubber
    EMAIL_RE,          # compiled regex
    COMMENT_TOKEN_RE,  # compiled regex
)
```

---

## Scrubber — what gets redacted

Both runtimes use byte-identical regex patterns:

| Pattern | Placeholder |
|---------|-------------|
| `user@host.tld` (RFC-5322-ish email) | `[EMAIL]` |
| `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx` (UUID v4 comment token) | `[COMMENT_TOKEN]` |

Fields visited: `message`, `exception.values[*].value`, `request.url`,
`request.query_string`, `request.data`, `breadcrumbs[*].message`,
`breadcrumbs[*].data`, `extra`, `tags`, `logentry` (Python only).

---

## Development

```sh
# JS
npm install
npm run build
npx vitest run

# Python
cd python
pip install -e ".[dev]"
pytest
```
