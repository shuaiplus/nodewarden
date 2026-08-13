# Official Bitwarden web vault (Pages)

This directory is the Cloudflare Pages frontend for the official Bitwarden OSS
self-host web vault (`@bitwarden/web-vault`). The NodeWarden Preact app in
`webapp/` stays on the Worker.

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
# Preferred: extract ghcr.io/bitwarden/web
npm run build:official-web

# Or build from a local clients checkout
BITWARDEN_CLIENTS=/path/to/bitwarden/clients npm run build:official-web
```

## Local

```bash
# Terminal 1 — Worker + local webapp
JWT_SECRET=… npm run dev

# Terminal 2 — official web on :8080, proxied to the Worker
WORKER_ORIGIN=http://127.0.0.1:8787 npm run dev:official-web
```

Set `WEB_VAULT_ORIGINS=http://127.0.0.1:8080` on the Worker so CORS and signup
accept the official-web origin.

## Deploy

```bash
WORKER_ORIGIN=https://<your-worker>.workers.dev npm run deploy:official-web
```

Then set the Pages project env `WORKER_ORIGIN` to the same Worker URL, and set
the Worker secret/var `WEB_VAULT_ORIGINS` to the Pages origin.
