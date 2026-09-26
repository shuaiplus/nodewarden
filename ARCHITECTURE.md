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

A cipher changes owner only through share (`PUT /api/ciphers/{id}/share`, bulk `PUT /api/ciphers/share`, plus POST aliases). `PUT /api/ciphers/{id}` keeps the stored `organizationId` and returns 400 "Organization mismatch" when the client sends a different one. Share moves only the caller's personal ciphers, at most `importItemLimit` per bulk call. Share and org cipher create (`POST /api/ciphers`, `/api/ciphers/create`) both need every collection to belong to the target org and be writable by the caller, otherwise 400 (not 403, which official clients treat as a revoked token and log out). Only full collection access may create an org cipher in no collection. Upstream drops unwritable ids silently instead. The ciphers, their collection links and their re-encrypted attachment keys are written in one D1 batch.

An org cipher's collections change through `PUT /api/ciphers/{id}/collections_v2` (member) or `/collections-admin` (Owner, Admin or `editAnyCollection`), plus POST aliases. Both add and drop only collections the caller may write: a member's non-readOnly assignments, or every org collection with full access or on the admin route. Links to other collections survive, as in upstream `CollectionCipher_UpdateCollections` and 1aed7ce03. The member route answers `optionalCipherDetails` with `unavailable: true` once the caller can no longer read the item.

Instance backups never include runtime auth state (`session`, `account`, `two_factor`, devices, auth requests, remembered 2FA tokens).

## Auth

Better Auth owns credential hashing (`$s2$` via `src/services/auth-password.ts`), the `session` / `account` / `two_factor` tables, and `/api/auth/*`. Official clients stay on Bitwarden `/identity` and `/api`; those handlers call Better Auth internally where useful and still mint HS256 access JWTs with `JWT_SECRET`. Refresh tokens are rows in `session`, not a separate table.

Official-web signup emails go through the Cloudflare Email Sending binding (`env.EMAIL.send()`). `EMAIL_FROM` must be on an onboarded sending domain. The Worker returns an empty JSON string from `send-verification-email` (never the JWT). Official self-host web still continues to the password form; the email link uses `/redirect-connector.html#finish-signup`. RFC documentation addresses such as `@example.com` get the same empty response without a send.

`better-auth-cloudflare` `withCloudflare()` is not used: its bundled drizzle types clash with 1.0-rc. `src/auth.ts` wires `drizzleAdapter`, KV secondary storage, and `cf-connecting-ip` directly. Worker `nodejs_compat` is required.

## Organization invites

Members move Invited (0) → Accepted (1) → Confirmed (2), as upstream. Invite, and SCIM for an existing account, stores an Invited row with no user and mails its accept link; SCIM answers 409 for an address or `externalId` already in the org, as upstream. Only the invitee can accept it, with the emailed `ORG_INVITE_TTL_DAYS` token, and only Accepted rows can be confirmed. Before confirming, clients read the member's RSA public key from `GET /api/users/{id}/public-key` (any logged-in caller, also used for emergency access) or, in bulk, `POST /api/organizations/{orgId}/users/public-keys` (member managers; Accepted members of that org only). Any confirmed member can list every member's id, user id, role, status, name and email from `GET /api/organizations/{orgId}/users/mini-details`, as upstream, which official web's collection and group dialogs need; it carries no keys, permissions or 2FA state. Invite takes 1 to 20 valid addresses per request, as upstream. Invite mail needs `EMAIL`, `EMAIL_FROM` and `WEB_VAULT_ORIGINS`; the link never follows `X-Forwarded-Host`, the org name in the subject and body is defused with `sanitizeForEmail`, and RFC documentation addresses are skipped. Mail goes out before the row is saved, so a failed send (502) leaves no row for a retry to duplicate; upstream deletes the rows instead. Without mail, invites cannot be accepted yet. Upgrading from earlier builds: they auto-Accepted existing accounts without consent, so review Accepted (status 1) members and delete and re-invite any you did not expect.

Invite and `PUT /api/organizations/{orgId}/users/{id}` grant direct collection access only where the caller may modify it: Owners, Admins and `editAnyCollection` members anywhere, anyone else only on collections it holds with the stored Manage flag, directly or via a group ("Can edit" does not count). Anything else is 404 "Resource not found.", except an entry that repeats the member's current access unchanged, because official web offers every collection it shows. PUT keeps the member's access to collections the caller cannot modify, whether re-posted or omitted. A member without full collection access editing itself gets 400 "You cannot add yourself to a collection." for a new collection, and its posted groups are ignored. This is upstream `GetAuthorizedCollectionsToSaveAsync` with `allowAdminAccessToAllCollectionItems` off, applied to everyone but Owners and Admins, although `org-response.ts` advertises that setting as on; with it on, upstream lets `manageUsers` alone grant any collection. Group membership on invite or PUT stays unchecked, as upstream.
