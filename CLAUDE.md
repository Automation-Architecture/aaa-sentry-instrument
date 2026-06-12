# aaa-sentry-instrument — Claude Code Instructions

This repo holds two packages that wire Sentry (error monitoring) into AAA
apps in one step:

| Package | Location | Install |
|---------|----------|---------|
| JS / TypeScript (Next.js) | repo root | `npm install github:Automation-Architecture/aaa-sentry-instrument` |
| Python (FastAPI) | `python/` | `pip install "git+https://github.com/Automation-Architecture/aaa-sentry-instrument.git#subdirectory=python"` |

## Single source of truth — the scrubber

The PII scrubber is the heart of this package. There are **two twins** that
must stay byte-for-byte equivalent in their regex patterns:

- **JS canonical**: `src/scrub.ts` — exports `scrubEvent`
- **Python canonical**: `python/aaa_sentry_instrument/scrub.py` — exports `scrub_pii`

If a regex changes in one, change it in the other in the same commit and
update both test files (`__tests__/scrub.test.ts` and
`python/tests/test_scrub.py`). The pinned-pattern tests will catch drift.

## Workflow

Standard AAA PR flow applies: topic branch → PR → deliberate review via the
`/code-review` skill and/or human review → `aaa-merge <PR#>`. (CodeRabbit and
the Copilot PR reviewer were removed org-wide 2026-06-11; nothing auto-reviews
or gates merges.) The `.github/workflows/` files are copied from the org
`.github` repo; do not edit them here — pull updates from upstream.

## Local verification

JS:
```sh
npm install
npm run build
npx vitest run
```

Python:
```sh
cd python
pip install -e ".[dev]"
pytest
```

## Releasing / consuming

After pushing to `main`, downstream apps pull the latest by re-running their
install command. There is no versioned release process — the `main` branch IS
the release.
