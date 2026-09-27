# Official Bitwarden web vault (Pages)

This directory is the Cloudflare Pages frontend for the Bitwarden self-host web
vault (`@bitwarden/web-vault`), with a small NodeWarden organization-creation
patch. The NodeWarden Preact app in `webapp/` stays on the Worker.

```
browser  →  Pages (official Angular vault)
                │  /api /identity /icons /notifications …
                ▼
           Worker (NodeWarden APIs + optional local webapp)
```

The official vault always uses `window.location.origin` as its API base. Pages
must therefore proxy backend paths to the Worker (`functions/_middleware.js`).

## Build

```bash
npm run build:official-web

# Optionally use an existing clients repository instead of downloading it
BITWARDEN_CLIENTS=/path/to/bitwarden/clients npm run build:official-web
```

The build pins `web-v2026.9.0` (`7ecf0d710cf39db40aa4db1c611417af2a0f44e0`)
and applies [the organization patch](patches/organization-create.patch) in an
isolated checkout at `.tmp/official-web-source`. It leaves the supplied clients
checkout unchanged. The full self-hosted build includes the Secrets Manager
screens; the OSS entry point includes only their landing page. Upstream license
files are retained, and source maps are omitted from the Pages upload.

Creating an organization asks for its name, generates and wraps its keys in the
browser using the existing Bitwarden code, and posts to NodeWarden's ordinary
organization API. No license file is needed. Creation from the Secrets Manager
landing page opens the new organization's Secrets Manager.

## Local

```bash
# Terminal 1 — Worker + local webapp
JWT_SECRET=… npm run dev

# Terminal 2 — official web on :8080, proxied to the Worker
WORKER_ORIGIN=http://127.0.0.1:8787 npm run dev:official-web
```

Set `WEB_VAULT_ORIGINS=http://127.0.0.1:8080` on the Worker so CORS and signup
accept the official-web origin.

Official signup emails are sent by the Worker via Cloudflare Email Sending
(`EMAIL` binding, `EMAIL_FROM` on an onboarded domain). The send-verification
endpoint returns an empty JSON string. The self-hosted client continues to the
password form; the emailed `/redirect-connector.html#finish-signup?...` link
carries the verification token when opened.

## Browser checks

`npm run test:e2e:official` requires the built client to report version `2026.9.0`.
Point `E2E_ORIGIN` at an isolated local Worker with the local email simulator, and
`OFFICIAL_WEB_ORIGIN` at its HTTPS official-web proxy. The SDK requires HTTPS.

The organization test additionally takes `E2E_OFFICIAL_ORG_FIXTURE`, a private JSON
file with `{pagesOrigin, email, password}` for a disposable account with real
encrypted keys and no organizations. It only accepts localhost. It checks blank
names, organization creation without a file, encrypted keys/default collection,
navigation to Secrets Manager, and encrypted project creation and display.

## Deploy

Set `WORKER_ORIGIN` in `official-web/wrangler.toml` to the Worker URL and the
Worker's `WEB_VAULT_ORIGINS` to the Pages origin. Then run:

```bash
npm run deploy:official-web
```

Deployment runs from `official-web/`, uploads its `dist/` directory and includes
`functions/_middleware.js`. The root `dist/` is the separate Worker webapp.
Publish from the Pages production branch (`main` for this deployment), or pass
`-- --branch main` to the npm command; other branches create preview deployments.
