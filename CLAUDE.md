# NodeWarden agent notes

Bitwarden-compatible Cloudflare Worker. See `ARCHITECTURE.md` and `docs/`.

## Conventions

- Schema lives in `src/db/schema.ts` (+ `relations.ts`). Generate with `npm run db:generate` (drizzle-kit + embed). Bump `STORAGE_SCHEMA_VERSION` in `src/db/migrate.ts`. Data-only fixes: `npx drizzle-kit generate --custom --name <slug>`, write the SQL, `npm run db:embed`; keep it replay-safe (each bump replays every migration).
- D1: `db.batch()` only; never `db.transaction()`. Chunk at 100 bound parameters.
- Auth engine is Better Auth (`src/auth.ts`). Bitwarden `/identity` and `/api` stay adapters. Sessions live in `session`, credentials in `account`. Access JWTs stay HS256 via `JWT_SECRET`. Do not add `withCloudflare()` (drizzle 1.0-rc type clash).
- Personal vault queries and mutations must exclude `organization_id IS NOT NULL`. Org cipher access goes through `src/handlers/cipher-access.ts`.
- Do not store plaintext vault or SM values.
- Official Bitwarden clients are the API contract; Vaultwarden is the AGPL reference.
- The only web vault is the official Bitwarden web in `official-web/` (Pages), which proxies `/api` `/identity` to the Worker via `WEB_VAULT_ORIGINS`. The Worker serves no web UI besides `/admin`; its static assets (`public/`) are only the WebAuthn and SSO connector pages official clients open on the server origin.
- Official web signup uses `/identity/accounts/register/send-verification-email` + `/finish`. Send a Cloudflare Email (`EMAIL` binding + `EMAIL_FROM`) and return an empty JSON string (never an inline JWT). Official self-host web still continues to the password form; the emailed `/redirect-connector.html#finish-signup` link carries the token when the user opens it.
- The patched Pages web vault creates orgs by name via `POST /api/organizations`, preserving client-generated encrypted keys. Unmodified self-host web uses `POST /organizations/licenses/self-hosted` (any JSON); keep `GET /api/licenses/nodewarden-enterprise.json` for it. Emergency access lives in `emergency_access`.
- Prefer Cloudflare D1 / KV / DO / Queues / Workflows / R2 over new in-process state.
- Files > 100 MB upload via R2 S3 presigned URLs (`src/services/r2-presign.ts`).
- Tests: `npm test` runs `src/**/*.test.ts` and `scripts/*.test.{ts,mjs}`. Route tests among them drive the real Worker `fetch` via `scripts/support/env.ts` (`createTestEnv`, `seedUser`, `authedFetch`) on a SQLite-backed D1 that enforces the 100-parameter cap and batch atomicity. `npx tsc --noEmit` skips `scripts/` and tests.
- Routing is a Hono 4 app (`src/router.ts` + `src/router-*.ts`). Handlers keep their `(request, env, …)` signatures and routes call them with `c.req.raw`. Paths match exact case except the Secrets Manager sub-router, which lower-cases its path. Read JSON bodies with `parseJsonBody` (`src/utils/response.ts`), which normalizes PascalCase keys; `prop` / `readString` accept either casing.
- Repositories (`src/services/storage-*-repo.ts`) are called directly with `env.DB`; there is no storage facade. `shared/backend-paths.ts` is the single list of backend path prefixes for the Pages proxy, the local official-web server and web-vault visibility.
- Validate input with zod, never hand-rolled typeof chains: request bodies through `parseBody(request, Schema)`, Worker variables through `readEnvConfig(env)` (`src/config/env.ts`), stored JSON through schemas with `.catch` fallbacks. Keep user-facing error messages stable; tests pin them.
- Prefer installed packages over hand-rolled helpers: `hono/jwt`, `hono/utils/encode`, `hono/utils/crypto`, `hono/utils/cookie`, `hono/cors`, `hono/html`, `hono/utils/ipaddr`, `aws4fetch`, `otpauth`. Constant-time comparisons use `constantTimeEquals` (`src/utils/api-key.ts`). Construct `new RateLimitService(env)`; per-minute budgets need a matching `[[ratelimits]]` binding in both wrangler configs.
- Parallel agent worktrees share `refs/stash`; never use `git stash` there (the user keeps a stash of their own).

- SM authorization goes through `src/services/sm-authz.ts` + `smContext`; no ad-hoc checks.

- Machine JWTs carry `type=ServiceAccount`; only `router-sm`'s machine allowlist accepts them.

- SM access = confirmed member, independent of licenses. Owners/Admins have full access; other members use object policies.

- All transactional mail goes through `sendMail` and data-only templates. Links use configured vault origins or the Worker request origin, never `X-Forwarded-Host`.
- Portal admins come from `ADMIN_EMAILS`, independently of `users.role`; portal handlers render HTML and never call `errorResponse`. Keep `/admin` off the official-web Pages proxy.

- With `ADMIN_EMAILS` configured, `users.role` is derived by `syncVaultAdminRoles` from verified addresses, with a no-lockout guard. Do not write roles outside the guarded bootstrap, sync, or backup-import paths. Account creation uses `createUser` (INSERT); `saveUser` only UPDATEs its explicit field list, defaulting to profile fields. Never write a whole stale account snapshot. Saves compare the original security stamp and return false on a lost update; credential writers must reject that result. Role, status, email verification, recovery codes and Email 2FA use targeted writers.

- Email codes go only through `src/services/email-otp.ts`: purpose/binding-scoped, hashed at rest, single-use, budgeted and five-minute expiry.

- Bitwarden event history is `events` via `recordEvents`/`recordUserEvent`/`recordSendEvent` in `src/services/events.ts`, called with the request after the committed write and only on real transitions; never store names, values or ciphertext. Reads go through `listEventsResponse` with an explicit authorized scope (`accessEventLogs` for organizations) and refuse with 404, never 403. Prune by receipt age only, never a shared row cap. `audit_logs` stays the separate administrator log.

- Email changes must atomically update the normalized email, verified flag, server hash, client-rewrapped key and credential mirror, rotate the stamp and revoke sessions. Better Auth `user.changeEmail` and `user.deleteUser` stay disabled; they bypass vault key and deletion invariants.
