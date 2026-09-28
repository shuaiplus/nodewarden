# Official Bitwarden web vault

This directory builds the Bitwarden self-host web vault (`@bitwarden/web-vault`)
with a small NodeWarden organization-creation patch. It is the only web vault.
The Worker serves it as static assets on the same origin as the API, `/admin` and
the connector pages:

```
browser  →  Worker origin
              ├─ /api /identity /icons /notifications … /admin, our connector pages
              │     → Worker code (run_worker_first)
              └─ everything else → the official vault's files (index.html fallback)
```

The official vault always uses `window.location.origin` as its API base, and
WebAuthn only accepts a relying-party ID equal to the page's host or a parent of
it. Serving the vault and the API from one origin is what lets passkeys and
security keys work in the vault and in the official clients alike.

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
files are retained, and source maps are omitted.

`npm run build:assets` (run by wrangler before `deploy` and `dev`) copies
`dist/` into `dist/worker-assets/`, overlays our connector pages from `public/`
and writes the `_headers` file for the files Cloudflare serves directly.

Creating an organization asks for its name, generates and wraps its keys in the
browser using the existing Bitwarden code, and posts to NodeWarden's ordinary
organization API. No license file is needed. Creation from the Secrets Manager
landing page opens the new organization's Secrets Manager.

## Local

```bash
npm run build:official-web   # once per pinned release
JWT_SECRET=… npx wrangler dev --local-protocol https
```

Current official web builds refuse `http://` API calls, so serve the Worker over
HTTPS locally. Set `WEB_VAULT_ORIGINS` to the local Worker origin so signup and
invite links point back at it.

Official signup emails are sent by the Worker via Cloudflare Email Sending
(`EMAIL` binding, `EMAIL_FROM` on an onboarded domain). The send-verification
endpoint returns an empty JSON string. The self-hosted client continues to the
password form; the emailed `/redirect-connector.html#finish-signup?...` link
carries the verification token when opened.

## Browser checks

`npm run test:e2e:official` requires the built client to report version `2026.9.0`.
Point both `E2E_ORIGIN` and `OFFICIAL_WEB_ORIGIN` at an isolated local Worker over
HTTPS with the local email simulator.

The organization test additionally takes `E2E_OFFICIAL_ORG_FIXTURE`, a private JSON
file with `{pagesOrigin, email, password}` (`pagesOrigin` names the vault origin)
for a disposable account with real encrypted keys and no organizations. It only
accepts localhost. It checks blank names, organization creation without a file,
encrypted keys/default collection, navigation to Secrets Manager, and encrypted
project creation and display.

## Deploy

`npm run deploy` assembles the assets and uploads them with the Worker. Build the
official web first; `build:assets` stops with an error when `dist/` is missing.
