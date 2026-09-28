# Official Bitwarden web and E2E

## Two frontends

| Frontend | Path | Hosted as |
|---|---|---|
| Official Bitwarden OSS web | `official-web/` | Worker static assets (`npm run build:official-web`, assembled by `npm run build:assets`) |

The official vault (`ghcr.io/bitwarden/web` / `@bitwarden/web-vault` OSS self-host) always uses `window.location.origin` as its API base, and WebAuthn only accepts a relying-party ID equal to the page's host or a parent of it. The Worker therefore serves the vault itself: the official build and our connector pages are its static assets, and `run_worker_first` sends the backend paths from `shared/backend-paths.ts`, `/admin` and our own pages to the Worker code. Cloudflare serves every other file directly, with the `_headers` that `scripts/build-worker-assets.mjs` writes, and falls back to `index.html`. Pages could not work for passkeys: `pages.dev` and `workers.dev` are public suffixes, so no relying-party ID covers both.

Set `WEB_VAULT_ORIGINS` to the Worker origin; mail links and invites use it. Config responses build their environment URLs from the request origin.

## Official signup

Current official clients do **not** POST `/api/accounts/register`. They:

1. `POST /identity/accounts/register/send-verification-email`
2. The server returns an empty JSON string and sends a verification link. Official self-host web can continue to `POST /identity/accounts/register/finish`; the emailed finish-signup link carries the token when opened.

NodeWarden never returns an inline registration JWT. Email is sent in the background with uniform responses; disabled or misconfigured email returns 503 for all addresses. Registration accepts both the new `masterPasswordAuthentication` / `masterPasswordUnlock` body and the older flat body. Set `ALLOW_OPEN_REGISTRATION=1` to allow official-client signups after the first admin without a NodeWarden invite code.

## E2E

Bitwarden’s public clients repo has **no** web Playwright suite. Their published Playwright project (`bitwarden/browser-interactions-testing`) is extension autofill against static pages, not a server.

Official web 2026.9.0 (`ghcr.io/bitwarden/web:latest`) ships `window.bitwardenAutomationDriver` in production builds (`featureFlags`, `state`, `lock`, `logging`, `processReload`); the 2026.7.1 extract does not. Current official web and `bw` CLI builds refuse `http://` servers, so the vault must be served over TLS. Reuse plan for upstream tests: [2026-09-25-upstream-e2e-reuse.md](../research/2026-09-25-upstream-e2e-reuse.md).

NodeWarden therefore runs:

- `npm run test:e2e` — API + official-web smoke against the Worker
- `npm run test:e2e:official` — official identity register + official Angular vault load from the Worker, organization creation without a license, and the Admin Console reporting journey

`e2e/official-org-reporting.spec.ts` opts in with `E2E_OFFICIAL_REPORT_FIXTURE`, a JSON file naming a disposable HTTPS `localhost` vault origin, a synthetic account and the ids of one encrypted weak-password login, one group and one Secrets Manager project created through the API. It asserts web 2026.9.0, then checks the weak-password report over `GET /api/ciphers/organization-details`, remediates the item through `PUT /api/ciphers/{id}/admin` with a re-encrypted password (the dialog stays open in view mode; closing it refreshes the report), reloads and unlocks to prove the ciphertext persisted, reads the member access report, and finally checks the event log for the typed item and project events plus an empty date range. Nothing in it mocks API responses or sends plaintext vault data.

```bash
npm run dev -- --local-protocol https
E2E_ORIGIN=https://localhost:8787 npm run test:e2e:official
```
