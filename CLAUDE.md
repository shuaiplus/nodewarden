# NodeWarden agent notes

Bitwarden-compatible Cloudflare Worker. See `ARCHITECTURE.md` and `docs/`.

## Conventions

- Schema lives in `src/db/schema.ts` (+ `relations.ts`). Generate with `npm run db:generate` (drizzle-kit + embed). Bump `STORAGE_SCHEMA_VERSION` in `src/services/storage.ts`.
- Auth engine is Better Auth (`src/auth.ts`). Bitwarden `/identity` and `/api` stay adapters. Sessions live in `session`, credentials in `account`. Access JWTs stay HS256 via `JWT_SECRET`.
- Personal vault queries must exclude `organization_id IS NOT NULL`.
- Do not store plaintext vault or SM values.
- Official Bitwarden clients are the API contract; Vaultwarden is the AGPL reference.
- Keep `webapp/` on the Worker. Official Bitwarden web lives in `official-web/` (Pages) and proxies `/api` `/identity` to the Worker via `WEB_VAULT_ORIGINS`.
- Official web signup uses `/identity/accounts/register/send-verification-email` + `/finish` (no email; return a register-verify JWT).
- Official self-host web creates orgs via `POST /organizations/licenses/self-hosted` (any JSON). Serve `GET /api/licenses/nodewarden-enterprise.json`. Emergency access lives in `emergency_access`.
- Prefer Cloudflare D1 / KV / DO / Queues / Workflows / R2 over new in-process state.
- Files > 100 MB upload via R2 S3 presigned URLs (`src/services/r2-presign.ts`).
