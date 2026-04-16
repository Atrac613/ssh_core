# ssh_core

`ssh_core` is an architecture-first Dart package for building an SSH client
stack. It defines the public API surface and the boundaries between transport,
authentication, channels, sessions, PTY handling, exec, SFTP, and port
forwarding.

## Scope

This repository currently provides the package structure and the core
interfaces. It is designed so the protocol implementation can be added in
layers without changing the top-level API shape.

Implemented in this scaffold:

- `SshClient` orchestration and connection state management
- transport, auth, channel, session, PTY, exec, SFTP, and forwarding contracts
- transport banner parsing/exchange helpers and binary packet framing helpers
- a smoke test that exercises the package with fake implementations
- example wiring showing how a concrete implementation can plug into the stack

Not implemented yet:

- real socket-based transport I/O
- key exchange and encryption
- message authentication, compression, and rekeying
- concrete password/public-key/keyboard-interactive exchanges
- real channel multiplexing, SFTP packets, and port forwarding streams

## Public modules

- `transport`: socket lifecycle, handshake metadata, and global requests
- `auth`: authentication strategies and auth results
- `channels`: generic channel open/request lifecycle
- `sessions`: shell/session abstractions
- `pty`: terminal allocation and resize metadata
- `exec`: non-interactive command execution
- `sftp`: file transfer subsystem contracts
- `port forwarding`: local, remote, and dynamic forwarding contracts

## Example

```dart
import 'package:ssh_core/ssh_core.dart';

Future<void> main() async {
  final client = SshClient(
    config: const SshClientConfig(
      host: 'example.com',
      username: 'demo',
    ),
    authMethods: const [
      SshPasswordAuthMethod(password: 'secret'),
    ],
    transport: DemoTransport(),
    authenticator: DemoAuthenticator(),
    channelFactory: DemoChannelFactory(),
    sessionManager: DemoSessionManager(),
    execService: DemoExecService(),
    sftpSubsystem: DemoSftpSubsystem(),
    portForwardingService: DemoPortForwardingService(),
  );

  await client.connect();
  final result = await client.exec('uname -a');
  print(result.stdoutText);
  await client.close();
}
```

See `example/ssh_core_example.dart` for a complete compiling example.

## Transport Primitives

The transport module now includes low-level helpers for the earliest SSH
handshake steps:

- `SshTransportBanner` and `SshBannerExchange` for SSH identification strings
- `SshPacketCodec` for SSH binary packet framing
- `SshPacketReader` for reading framed packets from chunked byte streams

These helpers intentionally stop short of encryption, MAC verification, and
socket ownership. They are meant to be reused by a future concrete transport
implementation.

## Suggested implementation order

1. transport socket integration around packet codec and banner exchange
2. key exchange and host-key verification
3. user authentication service
4. channel multiplexer and session channels
5. exec and shell requests with PTY support
6. SFTP subsystem
7. local, remote, and dynamic port forwarding
