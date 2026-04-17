# ssh_core

[![CI](https://github.com/Atrac613/ssh_core/actions/workflows/dart.yml/badge.svg)](https://github.com/Atrac613/ssh_core/actions/workflows/dart.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`ssh_core` is an experimental Dart SSH client core that focuses on protocol
building blocks rather than a single monolithic client implementation.

It defines clear boundaries between transport, authentication, channels,
sessions, PTY handling, exec, SFTP, and port forwarding so higher-level
packages or applications can compose the pieces they need.

## Status

This repository is public and useful today for:

- SSH protocol exploration and interoperability work
- building custom SSH clients on top of packet-capable abstractions
- iterating on transport/auth/channel behavior in pure Dart

Current status:

- the package is still experimental
- `publish_to: none` is still set, so it is not ready for `pub.dev`
- the public API is intentionally small, but some low-level transport details
  are still evolving

## What It Is

- A Dart-first SSH client core with separable modules
- A transport layer with real secure socket support
- A protocol toolkit for auth, channels, sessions, SFTP, and forwarding
- A codebase aimed at incremental implementation rather than big rewrites

## What It Is Not

- A polished end-user SSH CLI
- A stable `1.0` API
- A full interoperability matrix across every SSH server and algorithm variant
- A replacement for OpenSSH

## Highlights

- `SshClient` orchestration with injectable transport/auth/session services
- `SshSecureSocketTransport` with:
  - Curve25519 key exchange
  - Ed25519 / RSA / ECDSA host-key verification
  - `chacha20-poly1305@openssh.com`
  - `aes128-ctr`, `aes192-ctr`, `aes256-ctr`
  - `hmac-sha2-256`, `hmac-sha2-512`
  - `zlib` and `zlib@openssh.com`
  - mid-session rekeying
- Packet-backed channel, shell, exec, SFTP, and forwarding services
- Local, remote, and dynamic TCP port forwarding bridges
- Focused tests plus a package-level smoke test
- A live `dart:io` example via `SshIoClientFactory`

## Getting Started

The package is not published on `pub.dev` yet.

For local development, a path dependency is still convenient:

```yaml
dependencies:
  ssh_core:
    path: ../ssh_core
```

For GitHub-based integration, depend on the repository directly:

```yaml
dependencies:
  ssh_core:
    git:
      url: https://github.com/Atrac613/ssh_core.git
```

## Quick Start

```dart
import 'package:ssh_core/ssh_core.dart';

Future<void> main() async {
  final trustedHostKey = SshHostKey.decode(
    (SshPayloadWriter()
          ..writeString('ssh-ed25519')
          ..writeStringBytes(const [1, 2, 3, 4, 5, 6]))
        .toBytes(),
  );

  final client = SshClient(
    config: SshClientConfig(
      host: 'example.com',
      username: 'demo',
      hostKeyVerifier: SshStaticHostKeyVerifier(
        trustedKeys: <SshTrustedHostKey>[
          SshTrustedHostKey(host: 'example.com', hostKey: trustedHostKey),
        ],
      ),
    ),
    authMethods: const <SshAuthMethod>[
      SshPasswordAuthMethod(password: 'secret'),
    ],
    transport: DemoTransport(hostKey: trustedHostKey),
    authenticator: DemoAuthenticator(),
    channelFactory: DemoChannelFactory(),
    sessionManager: DemoSessionManager(),
    execService: DemoExecService(),
    sftpSubsystem: DemoSftpSubsystem(),
    portForwardingService: DemoPortForwardingService(),
  );

  await client.connect();
  final result = await client.exec('uname -a');
  print(result.stdoutText.trim());
  await client.close();
}
```

For complete examples:

- [`example/ssh_core_example.dart`](example/ssh_core_example.dart): fake/demo
  wiring that compiles quickly
- [`example/ssh_core_io_example.dart`](example/ssh_core_io_example.dart): live
  `dart:io` example built on `SshIoClientFactory`

## Public API

The main package entry points are:

- `package:ssh_core/ssh_core.dart`
- `package:ssh_core/ssh_core_io.dart`

Primary public surfaces:

- `SshClient`: top-level orchestration
- `SshTransport` / `SshPacketTransport`: transport contracts
- `SshSecureSocketTransport`: real secure `dart:io` transport
- `SshAuthenticator` and protocol auth helpers
- `SshPacketChannelFactory`: packet-backed channel multiplexer
- `SshProtocolSessionManager`: shell sessions with PTY/env requests
- `SshProtocolExecService`: non-interactive command execution
- `SshProtocolSftpSubsystem`: packet-backed SFTP client
- `SshIoPortForwardingService`: local/remote/dynamic forwarding bridges
- `SshIoClientFactory`: convenience wiring for live clients

## Transport Coverage

Transport primitives currently include:

- SSH identification banner parsing and exchange
- packet framing and payload codecs
- `KEXINIT`, ECDH init/reply, `NEWKEYS`, disconnect, and ext-info messages
- algorithm negotiation helpers
- host-key parsing and verification helpers
- exchange-hash and key-derivation helpers
- encrypted packet protection for AES-CTR/HMAC and ChaCha20-Poly1305

Not implemented yet:

- strict-kex / full Terrapin-oriented transport hardening
- broader KEX coverage beyond the current Curve25519 baseline
- broader cipher / MAC coverage beyond the current explicit matrix

## Compatibility Matrix

Current secure transport interoperability is intentionally narrow and explicit:

| Category | Supported |
| --- | --- |
| KEX | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| Host key | `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` |
| Cipher | `chacha20-poly1305@openssh.com`, `aes128-ctr`, `aes192-ctr`, `aes256-ctr` |
| MAC | embedded Poly1305 for `chacha20-poly1305@openssh.com`; `hmac-sha2-256`, `hmac-sha2-512` for AES-CTR |
| Compression | `none`, `zlib`, `zlib@openssh.com` |
| Auth | `none`, `password`, `publickey`, `keyboard-interactive` |
| Forwarding | local, remote, dynamic TCP forwarding, including assigned remote ports |

## Repository Layout

- `lib/ssh_core.dart`: main public exports
- `lib/ssh_core_io.dart`: `dart:io`-specific exports
- `lib/src/transport/`: handshake, crypto, packet protection, secure transport
- `lib/src/auth/`: auth models and protocol authenticator
- `lib/src/channels/`: channel contracts and packet-backed implementation
- `lib/src/sessions/`: shell/session abstractions and helpers
- `lib/src/exec/`: non-interactive exec abstractions and implementation
- `lib/src/sftp/`: SFTP contracts and packet-backed subsystem
- `lib/src/forwarding/`: forwarding contracts, protocol helpers, IO bridges
- `example/`: usage examples
- `test/`: focused tests
- `tool/smoke_test.dart`: lightweight end-to-end sanity check

## Development

Run the standard verification set:

```sh
dart format .
dart analyze
dart test
dart run tool/smoke_test.dart
```

GitHub Actions runs the same checks in `.github/workflows/dart.yml`.

If you want to contribute, see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Please also follow the lightweight expectations in
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Roadmap

### Now

- finish the in-flight transport hardening work around `strict-kex`,
  `ext-info`, and clearer disconnect/error surfacing
- keep strengthening focused tests for transport, auth, session lifecycle, and
  forwarding shutdown paths
- continue improving OpenSSH interoperability without widening the public API
  unnecessarily

### Next

- broaden algorithm coverage beyond the current Curve25519 +
  Ed25519/RSA/ECDSA + ChaCha20/AES-CTR + HMAC-SHA2 baseline
- add more interoperability-focused integration coverage
- tighten host-key trust UX for real applications

### Later

- add advanced forwarding variants beyond TCP local/remote/dynamic bridges
- keep growing the live `dart:io` examples into copy-pasteable integration
  recipes
- prepare the package for a first public version and, eventually, `pub.dev`

## Publishing Notes

Before tagging the first public GitHub release, it is worth checking:

- the README still matches the actual compatibility matrix and examples
- the MIT license remains the intended choice
- GitHub Actions is green on `main` and on pull requests
- issue and pull request templates still match the current maintenance workflow
- release notes describe the experimental scope and known gaps
