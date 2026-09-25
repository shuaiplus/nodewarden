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

Official-web signup emails go through the Cloudflare Email Sending binding (`env.EMAIL.send()`). `EMAIL_FROM` must be on an onboarded sending domain. The Worker returns an empty JSON string from `send-verification-email` (never the JWT). Official self-host web still continues to the password form; the email link uses `/redirect-connector.html#finish-signup`. RFC documentation addresses such as `@example.com` get the same empty response without a send.

`better-auth-cloudflare` `withCloudflare()` is not used: its bundled drizzle types clash with 1.0-rc. `src/auth.ts` wires `drizzleAdapter`, KV secondary storage, and `cf-connecting-ip` directly. Worker `nodejs_compat` is required.

## Organization invites

Members move Invited (0) → Accepted (1) → Confirmed (2), as upstream. Invite, and SCIM for an existing account, stores an Invited row with no user. Only the invitee can accept it, with the emailed `ORG_INVITE_TTL_DAYS` token, and only Accepted rows can be confirmed. Before confirming, clients read the member's RSA public key from `GET /api/users/{id}/public-key` (any logged-in caller, also used for emergency access) or, in bulk, `POST /api/organizations/{orgId}/users/public-keys` (member managers; Accepted members of that org only). Invite takes 1 to 20 valid addresses per request, as upstream. Invite mail needs `EMAIL`, `EMAIL_FROM` and `WEB_VAULT_ORIGINS`; the link never follows `X-Forwarded-Host`, the org name in the subject and body is defused with `sanitizeForEmail`, and RFC documentation addresses are skipped. Without mail, invites cannot be accepted yet. Upgrading from earlier builds: they auto-Accepted existing accounts without consent, so review Accepted (status 1) members and delete and re-invite any you did not expect.
