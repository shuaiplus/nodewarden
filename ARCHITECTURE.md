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
- Auth engine: Better Auth (`src/auth.ts`) behind Bitwarden `/identity` and `/api` adapters
- Blobs: R2 or KV (`src/services/blob-store.ts`)
- Push: `NotificationsHub` Durable Object
- Backups: `BackupTransferRunner` Durable Object
- Web vaults:
  - Local: `webapp/` (Preact + Vite) → Worker assets (`dist/`)
  - Official: `official-web/` (Bitwarden OSS self-host Angular) → Cloudflare Pages, API proxied to the Worker

## Data

Schema lives in `src/db/schema.ts` and `src/db/relations.ts` (relations v2). `npm run db:generate` emits nested `migrations/<id>/migration.sql` and embeds SQL into `src/db/baseline.ts` for Worker bootstrap. Bump `STORAGE_SCHEMA_VERSION` when the schema changes.

Use `db.batch()` for multi-statement work. `db.transaction()` is broken on D1. D1 caps one statement at 100 bound parameters.

Personal vault lists and mutations filter `organization_id IS NULL`. Organization ciphers are loaded by id, then membership and collection ACL in `src/handlers/cipher-access.ts`.

Instance backups never include runtime auth state (`session`, `account`, `two_factor`, devices, auth requests, remembered 2FA tokens).

## Auth

Better Auth owns credential hashing (`$s2$` via `src/services/auth-password.ts`), the `session` / `account` / `two_factor` tables, and `/api/auth/*`. Official clients stay on Bitwarden `/identity` and `/api`; those handlers call Better Auth internally where useful and still mint HS256 access JWTs with `JWT_SECRET`. Refresh tokens are rows in `session`, not a separate table.

Official-web signup emails go through the Cloudflare Email Sending binding (`env.EMAIL.send()`). `EMAIL_FROM` must be on an onboarded sending domain. The Worker returns an empty JSON string from `send-verification-email` (never the JWT); `/finish` requires the token from the message. RFC documentation addresses such as `@example.com` get the same empty response without a send.

`better-auth-cloudflare` `withCloudflare()` is not used: its bundled drizzle types clash with 1.0-rc. `src/auth.ts` wires `drizzleAdapter`, KV secondary storage, and `cf-connecting-ip` directly. Worker `nodejs_compat` is required.
