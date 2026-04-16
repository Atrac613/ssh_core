# AGENTS.md

## Project Snapshot

- Package name: `ssh_core`
- Language: Dart
- Status: architecture-first scaffold, not a complete SSH implementation yet
- Goal: provide stable building blocks for an SSH client library covering:
  - transport
  - auth
  - channels
  - sessions
  - PTY
  - exec
  - SFTP
  - port forwarding

The current repository defines the public API surface and the module boundaries.
Concrete protocol behavior should be added incrementally without casually
reshaping the top-level API.

## Source Of Truth

Read these first before making structural changes:

1. `README.md`
2. `lib/ssh_core.dart`
3. `lib/src/core/client.dart`
4. `tool/smoke_test.dart`
5. `example/ssh_core_example.dart`

## Repository Layout

- `lib/ssh_core.dart`
  - public export surface for consumers
- `lib/src/core/`
  - client orchestration, config, exceptions
- `lib/src/transport/`
  - connection lifecycle, handshake, transport-level requests
- `lib/src/auth/`
  - authentication methods and authenticator contract
- `lib/src/channels/`
  - channel open/request abstractions
- `lib/src/sessions/`
  - shell session abstractions
- `lib/src/pty/`
  - PTY metadata and resize config
- `lib/src/exec/`
  - non-interactive command execution
- `lib/src/sftp/`
  - file transfer contracts
- `lib/src/forwarding/`
  - local, remote, dynamic forwarding contracts
- `example/`
  - wiring example with fake implementations
- `tool/smoke_test.dart`
  - minimal end-to-end contract smoke test

## Working Agreements

- Preserve the architecture-first shape unless there is a clear reason to change
  it.
- Prefer extending internals over breaking exported API names or moving files.
- Keep modules cohesive. Transport/auth/channel/session responsibilities should
  stay clearly separated.
- Prefer dependency injection and narrow interfaces over hard-wiring concrete
  implementations into `SshClient`.
- Do not claim features are implemented unless they work end-to-end through the
  public API.
- Keep examples and smoke tests aligned with the current public API.
- Use ASCII unless an existing file already requires Unicode.

## Dart Conventions

- The repo uses strict analyzer settings:
  - `strict-casts: true`
  - `strict-inference: true`
  - `strict-raw-types: true`
- Lint expectations are defined in `analysis_options.yaml`.
- Prefer explicit types when they improve clarity.
- Keep public APIs small and intentional.
- Add comments sparingly, only when a protocol or state transition is not
  obvious from the code.

## Git Commit Messages

Use English commit messages in a modern Conventional Commits style.

Preferred format:

```text
type(scope): short imperative summary
```

Rules:

- Keep the subject line in English.
- Use the imperative mood, for example `add`, `fix`, `refactor`, `document`.
- Prefer a concise subject, ideally within 72 characters.
- Use a scope when it helps, especially for package modules such as `core`,
  `transport`, `auth`, `channels`, `sessions`, `pty`, `exec`, `sftp`,
  `forwarding`, `example`, and `docs`.
- Make each commit represent one logical change.
- Add a body when the reason, protocol impact, or migration detail is not
  obvious from the subject line alone.
- Mark breaking changes with `!` after the type or scope, and describe the
  impact in a `BREAKING CHANGE:` footer.

Recommended types:

- `feat`
- `fix`
- `refactor`
- `docs`
- `test`
- `chore`
- `build`
- `ci`
- `perf`

Examples:

```text
feat(transport): add packet reader scaffold
fix(auth): reject empty password auth attempts
refactor(core): simplify client connection state flow
docs(readme): document planned SFTP milestones
test(exec): cover exit code propagation
feat(core)!: rename shell session factory API

BREAKING CHANGE: `openShellSession` now requires an explicit channel request.
```

## Verification

Run these after meaningful changes:

```sh
dart format .
dart analyze
dart run tool/smoke_test.dart
```

If you add real protocol behavior, also add focused tests in `test/` where it
helps. Keep `tool/smoke_test.dart` passing as the lightweight package sanity
check.

## Current Priorities

Implement in this order unless the task says otherwise:

1. transport packet codec and protocol banner exchange
2. key exchange and host-key verification
3. authentication flows
4. channel multiplexing
5. session shell and exec requests with PTY support
6. SFTP subsystem
7. local, remote, and dynamic port forwarding

## Change Checklist

Before finishing work, make sure:

- exported symbols in `lib/ssh_core.dart` still match the intended public API
- `README.md` still reflects reality
- example code still compiles against the package
- smoke coverage still exercises the main client orchestration path
- new abstractions are placed in the correct module instead of the core client

## When Unsure

- Choose the smaller public API.
- Prefer additive changes over renames.
- Keep protocol details behind module-specific interfaces.
- Leave clear seams for future real implementations rather than overfitting fake
  scaffolding.
