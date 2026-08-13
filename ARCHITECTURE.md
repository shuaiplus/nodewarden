# NodeWarden architecture

Bitwarden-compatible password manager on Cloudflare Workers.

## Living docs

- [Organizations, SSO/SCIM, Secrets Manager, Cloudflare offload](docs/architecture/01-organizations-sso-sm-cloudflare.md)
- [Kubernetes secret operator](docs/architecture/02-k8s-secret-operator.md)
- [Official Bitwarden web (Pages) and E2E](docs/architecture/03-official-web-and-e2e.md)
- [Enterprise license upload and emergency access](docs/architecture/04-enterprise-license-emergency-access.md)
- [Research: Bitwarden / Vaultwarden parity](docs/research/2026-08-13-bitwarden-vaultwarden-orgs-sso-sm.md)

## Runtime

- Worker: `src/index.ts` → `src/router.ts`
- Data: D1 via Drizzle v1 (`src/db/`, `src/services/storage*.ts`, `migrations/`)
- Blobs: R2 or KV (`src/services/blob-store.ts`)
- Push: `NotificationsHub` Durable Object
- Backups: `BackupTransferRunner` Durable Object
- Web vaults:
  - Local: `webapp/` (Preact + Vite) → Worker assets (`dist/`)
  - Official: `official-web/` (Bitwarden OSS self-host Angular) → Cloudflare Pages, API proxied to the Worker
