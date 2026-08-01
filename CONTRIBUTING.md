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

## Recommended Checks

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

For documentation-only changes:

```sh
git diff --check
```
