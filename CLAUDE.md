# NodeWarden agent notes

Bitwarden-compatible Cloudflare Worker. See `ARCHITECTURE.md` and `docs/`.

## Conventions

- Schema lives in `src/db/schema.ts` (+ `relations.ts`). Generate with `npm run db:generate` (drizzle-kit + embed). Bump `STORAGE_SCHEMA_VERSION` in `src/services/storage.ts`.
- D1: `db.batch()` only; never `db.transaction()`. Chunk at 100 bound parameters.
- Auth engine is Better Auth (`src/auth.ts`). Bitwarden `/identity` and `/api` stay adapters. Sessions live in `session`, credentials in `account`. Access JWTs stay HS256 via `JWT_SECRET`. Do not add `withCloudflare()` (drizzle 1.0-rc type clash).
- Personal vault queries and mutations must exclude `organization_id IS NOT NULL`. Org cipher access goes through `src/handlers/cipher-access.ts`.
- Do not store plaintext vault or SM values.
- Official Bitwarden clients are the API contract; Vaultwarden is the AGPL reference.
- Keep `webapp/` on the Worker. Official Bitwarden web lives in `official-web/` (Pages) and proxies `/api` `/identity` to the Worker via `WEB_VAULT_ORIGINS`.
- Official web signup uses `/identity/accounts/register/send-verification-email` + `/finish`. Send a Cloudflare Email (`EMAIL` binding + `EMAIL_FROM`) and return an empty JSON string (never an inline JWT). Official self-host web still continues to the password form; the emailed `/redirect-connector.html#finish-signup` link carries the token when the user opens it.
- Official self-host web creates orgs via `POST /organizations/licenses/self-hosted` (any JSON). Serve `GET /api/licenses/nodewarden-enterprise.json`. Emergency access lives in `emergency_access`.
- Prefer Cloudflare D1 / KV / DO / Queues / Workflows / R2 over new in-process state.
- Files > 100 MB upload via R2 S3 presigned URLs (`src/services/r2-presign.ts`).
