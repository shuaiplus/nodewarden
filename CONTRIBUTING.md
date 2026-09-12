# Contributing to NodeWarden

Thanks for taking the time to improve NodeWarden.

NodeWarden is a Bitwarden-compatible server with a custom web vault, Cloudflare
Workers/D1 storage, attachment storage, imports/exports, and scheduled backups.
Small changes can affect official clients, backups, migrations, or locale files,
so please keep changes focused and check the related parts of the project.

## Before Opening an Issue

For bug reports, include enough detail for someone else to reproduce the problem:

- The client or browser you used.
- The page, API route, or action that failed.
- Screenshots, logs, or the exact error message.
- Whether the problem happened after sync, import, export, restore, upgrade, or
  a fresh deployment.

Please do not report NodeWarden-specific problems to the official Bitwarden
team. This project is independent from Bitwarden.

## Pull Request Guidelines

Keep pull requests small enough to review. A good PR should explain:

- What changed and why.
- What user-facing behavior changed.
- Which related areas were checked.
- Which commands were run before submitting.

Avoid mixing unrelated refactors with feature or bug-fix work. If a cleanup is
needed before the real fix, mention that clearly in the PR.

## Areas That Need Extra Care

Some parts of the codebase are deliberately connected. When changing one of
these areas, check the related files before calling the work complete.

### Database Changes

Runtime schema lives in `src/services/storage-schema.ts`. The initial D1 schema
lives in `migrations/0001_init.sql`.

If you add or change a table, column, or index:

- Update both schema files.
- Bump `STORAGE_SCHEMA_VERSION` in `src/services/storage.ts`.
- Decide whether the data should be included in instance backup.

### Backup And Restore

Backup export and restore are whitelist-based. This protects old backups from
breaking when fields are removed and prevents transient or secret runtime data
from being exported by accident.

When adding persistent data, check:

- `src/services/backup-archive.ts`
- `src/services/backup-import.ts`
- `webapp/src/lib/api/backup.ts`

Do not export runtime lock rows such as `backup.runner.lock.v1`. Do not import
retired sensitive fields such as `users.api_key`.

### Secrets And Provider Settings

Provider credentials must not be stored or exported as plain config JSON. Follow
the encrypted settings pattern in `src/services/backup-settings-crypto.ts`, or
document a replacement design before changing it.

### Bitwarden Client Compatibility

Official Bitwarden clients may send or expect fields that are not used directly
by the web vault. Cipher and sync changes should preserve unknown client fields
unless they are known-invalid or server-owned.

Check these files when changing vault item shape or sync behavior:

- `src/handlers/ciphers.ts`
- `src/handlers/sync.ts`
- `src/services/storage-cipher-repo.ts`

### Domain Rules

Equivalent-domain settings store both client/UI rule state and derived active
groups. Do not remove `equivalent_domains`, `custom_equivalent_domains`, or
`excluded_global_equivalent_domains` as duplicates without a migration and
compatibility plan.

### Accounts And Passwords

`users.master_password_hash` is for server-side login verification. It is not the
vault decryption key. Password changes, key material, `securityStamp`, and
refresh-token revocation must stay aligned.

Password hints are reminders, not recovery secrets. They must never contain the
master password, recovery codes, API keys, or anything that directly unlocks the
vault.

### i18n

Locale files are complete standalone bundles. When adding or changing user-facing
text, keep every locale in sync and run the validation script.

For new locales, update:

- `webapp/src/lib/i18n.ts`
- `webapp/src/lib/i18n/locales/*`
- `scripts/i18n-utils.cjs`

### Tests

`npm test` runs the whole suite. It needs no external services and no network: the
D1 and R2 bindings are backed by in-process implementations, so the tests execute
**real SQL** against the real schema (including the real shadow tables and the
final swap used by restore).

```sh
npm test
```

Files worth knowing about when adding a test:

- `scripts/lib/test-harness.ts` — shared fixture. Start from
  `createSchemaDatabase()` / `insertUser()` instead of building a database by hand;
  it also resets the process-scoped statics that would otherwise stop a second
  database from getting a schema.
- `scripts/lib/d1-sqlite.ts` — a `D1Database` on Node's built-in `node:sqlite`.
- `scripts/lib/r2-memory.ts` — in-memory attachment bucket.
- `scripts/lib/sql-recorder.ts` — records the statements that were run. Two
  counters, do not mix them up: `queries` counts prepared statements (use it for
  query-plan assertions) while `roundTrips` counts database round trips (use it
  for N+1 assertions). `batch([...])` is N prepares but **one** round trip.
- `scripts/lib/register-cloudflare-stub.mjs` — handler tests must be started as
  `tsx --import ./scripts/lib/register-cloudflare-stub.mjs`, because
  `cloudflare:workers` cannot be resolved under Node. This is already wired into
  every `test:*-handler` script; copy one of them when adding another.

Two rules that exist because each has already produced a false result:

- **Run the suite at least twice** before calling a change green. Some cleanup
  paths are gated on `Math.random()` and only run on a fraction of requests, so a
  single passing run can be luck. When testing such a path, pin `Math.random` for
  the duration of the test rather than hoping the path fires.
- **Never assert that two timestamps differ.** Calling `new Date().toISOString()`
  twice within the same millisecond returns the same value. Pin a baseline
  timestamp and assert that the new value is greater.

## Recommended Checks

Before opening a pull request, run the same command CI runs:

```sh
npm run verify
```

which is:

```sh
npm run typecheck   # tsconfig.json, webapp/, tsconfig.scripts.json, tsconfig.webapp-tests.json
npm run i18n:validate
npm test
npm run build
```

Narrower runs while iterating.

For most backend or shared changes:

```sh
npx tsc -p tsconfig.json --noEmit
npm run build
```

For webapp text or locale changes:

```sh
npm run i18n:validate
npx tsc -p webapp/tsconfig.json --noEmit
npm run build
```

For changes under `scripts/` (tests and tooling):

```sh
npx tsc -p tsconfig.scripts.json --noEmit
npm test
```

For documentation-only changes:

```sh
git diff --check
```
