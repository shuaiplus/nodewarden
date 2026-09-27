# Official Bitwarden web (Pages) and E2E

## Two frontends

| Frontend | Path | Hosted as |
|---|---|---|
| NodeWarden Preact vault | `webapp/` | Worker assets (`npm run build` → `dist/`) |
| Official Bitwarden OSS web | `official-web/` | Cloudflare Pages (`npm run build:official-web`) |

The official vault (`ghcr.io/bitwarden/web` / `@bitwarden/web-vault` OSS self-host) always uses `window.location.origin` as its API base. Pages therefore proxies `/api`, `/identity`, `/icons`, `/notifications`, `/scim`, `/sso`, `/config`, `/alive` to the Worker (`official-web/functions/_middleware.js`).

Set Worker `WEB_VAULT_ORIGINS` to the Pages origin so CORS, WebAuthn, and signup accept that origin. Config responses honor `X-Forwarded-Host` so `environment.vault` stays on the Pages origin.

## Official signup

Current official clients do **not** POST `/api/accounts/register`. They:

1. `POST /identity/accounts/register/send-verification-email`
2. The server returns an empty JSON string and sends a verification link. Official self-host web can continue to `POST /identity/accounts/register/finish`; the emailed finish-signup link carries the token when opened.

NodeWarden never returns an inline registration JWT. Email is sent in the background with uniform responses; disabled or misconfigured email returns 503 for all addresses. Registration accepts both the new `masterPasswordAuthentication` / `masterPasswordUnlock` body and the older local-webapp body. Set `ALLOW_OPEN_REGISTRATION=1` to allow official-client signups after the first admin without a NodeWarden invite code.

## E2E

Bitwarden’s public clients repo has **no** web Playwright suite. Their published Playwright project (`bitwarden/browser-interactions-testing`) is extension autofill against static pages, not a server.

Official web 2026.9.0 (`ghcr.io/bitwarden/web:latest`) ships `window.bitwardenAutomationDriver` in production builds (`featureFlags`, `state`, `lock`, `logging`, `processReload`); the 2026.7.1 extract does not. Current official web and `bw` CLI builds refuse `http://` servers, so the vault must be served over TLS. Reuse plan for upstream tests: [2026-09-25-upstream-e2e-reuse.md](../research/2026-09-25-upstream-e2e-reuse.md).

NodeWarden therefore runs:

- `npm run test:e2e` — API + official-web smoke against the Worker
- `npm run test:e2e:official` — official identity register + official Angular vault load through the Pages proxy, organization creation without a license, and the Admin Console reporting journey

`e2e/official-org-reporting.spec.ts` opts in with `E2E_OFFICIAL_REPORT_FIXTURE`, a JSON file naming a disposable HTTPS `localhost` Pages origin, a synthetic account and the ids of one encrypted weak-password login, one group and one Secrets Manager project created through the API. It asserts web 2026.9.0, then checks the weak-password report over `GET /api/ciphers/organization-details`, remediates the item through `PUT /api/ciphers/{id}/admin` with a re-encrypted password (the dialog stays open in view mode; closing it refreshes the report), reloads and unlocks to prove the ciphertext persisted, reads the member access report, and finally checks the event log for the typed item and project events plus an empty date range. Nothing in it mocks API responses or sends plaintext vault data.

```bash
npm run dev
OFFICIAL_WEB_PORT=8090 OFFICIAL_WEB_CERT=/tmp/nw-web.crt OFFICIAL_WEB_KEY=/tmp/nw-web.key \
  WORKER_ORIGIN=http://127.0.0.1:8787 npm run dev:official-web
E2E_ORIGIN=http://127.0.0.1:8787 OFFICIAL_WEB_ORIGIN=https://127.0.0.1:8090 npm run test:e2e:official
```
