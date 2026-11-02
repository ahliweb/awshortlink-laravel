## Summary
<!-- What changes and why. Link the issue (Fixes #123). -->

## Type
- [ ] Bug fix
- [ ] Feature
- [ ] Security hardening (non-sensitive — vulnerabilities are reported privately, see SECURITY.md)
- [ ] Docs / tooling

## Checklist
- [ ] `bash scripts/ci.sh` passes locally
- [ ] Tests added/updated (behavioural and security changes need a test in `tests/`)
- [ ] No secrets, credentials, personal data, hostnames or organisation branding added (see AGENTS.md)
- [ ] New tables have `ENABLE` + `FORCE` RLS policies and RLS test coverage
- [ ] New personal-data fields have a classification, retention rule and opt-in switch
- [ ] `CHANGELOG.md` and affected docs/OpenAPI/ADRs updated
