<!--
Thank you for the pull request. Keep the description factual and short.
Delete the sections that do not apply.
-->

## Summary

<!-- One or two sentences: what does this change, and why now. -->

## Change type

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation only
- [ ] Refactor with no behavioural change

## Verification

<!--
Which tests exercise the new behaviour? For bug fixes, link the specific test
that would have caught the bug on `main`.
-->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace` (relevant suites)
- [ ] New/changed behaviour has a regression test

## Audit-trail impact

<!--
Delete this section if the change does not touch receipts, the event chain,
JCS canonicalization, journals, session finalization, quotas, or identity.
Otherwise describe the invariant, why it still holds, and any migration notes.
-->

## Breaking changes / config or wire format

<!--
List every renamed or removed field, changed default, or format bump.
Include the migration path for existing deployments.
-->

## Related issues

<!-- e.g. Closes #123, Refs #456 -->
