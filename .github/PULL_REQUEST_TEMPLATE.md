## Summary

<!-- What changed and why? -->

## Change Type

- [ ] Bug fix
- [ ] Feature
- [ ] Compatibility update
- [ ] Documentation
- [ ] Refactor

## Cross-File Checklist

- [ ] I read `CONTRIBUTING.md`.
- [ ] Schema changes, if any, updated both runtime schema and `migrations/0001_init.sql`.
- [ ] Schema changes, if any, bumped `STORAGE_SCHEMA_VERSION` in `src/services/storage.ts`.
- [ ] Persistent data changes, if any, updated backup export/import or documented why backup is not needed.
- [ ] User-facing text changes, if any, updated all locale files.
- [ ] Bitwarden client compatibility was considered for sync/API shape changes.
- [ ] No secrets, tokens, private deployment values, or real vault data are included.

## Checks

- [ ] `npm run verify` — type checks for all four tsconfigs, `npm test`, `npm run i18n:validate`, `npm run build`
- [ ] New or changed tests: `npm test` was run at least twice (some cleanup paths are gated on `Math.random()`, so one green run can be luck)

## Notes

<!-- Anything reviewers should pay special attention to? -->
