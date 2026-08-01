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
- [ ] Persistent data changes, if any, updated backup export/import or documented why backup is not needed.
- [ ] User-facing text changes, if any, updated all locale files.
- [ ] Bitwarden client compatibility was considered for sync/API shape changes.
- [ ] No secrets, tokens, private deployment values, or real vault data are included.

## Checks

- [ ] `npx tsc -p tsconfig.json --noEmit`
- [ ] `npx tsc -p webapp/tsconfig.json --noEmit`
- [ ] `npm run i18n:validate`
- [ ] `npm run build`

## Notes

<!-- Anything reviewers should pay special attention to? -->
