# Contributing

Thanks for taking a look at `ssh_core`.

This repository is still experimental, so the most useful contributions are the
ones that improve correctness, interoperability, and test coverage without
reshaping the public API casually.

## Before You Change Code

- Read [`AGENTS.md`](AGENTS.md)
- Read [`README.md`](README.md)
- Prefer additive changes over renames
- Keep transport, auth, channel, session, and forwarding responsibilities
  clearly separated

## Recommended Workflow

1. Make one logical change at a time.
2. Add or update focused tests when behavior changes.
3. Keep the smoke test passing.
4. Use English Conventional Commits when preparing commits.

## Verification

Run:

```sh
dart format .
dart analyze
dart test
dart run tool/smoke_test.dart
```

## Good Contribution Targets

- transport hardening and interoperability fixes
- auth edge cases
- channel/session lifecycle fixes
- forwarding shutdown and backpressure behavior
- focused tests for protocol regressions
- documentation that matches reality

## Please Avoid

- large public API renames without a strong reason
- mixing unrelated refactors into protocol fixes
- claiming support for features that are not wired end-to-end
