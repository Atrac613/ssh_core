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
- a smoke test that exercises the package with fake implementations
- example wiring showing how a concrete implementation can plug into the stack

Not implemented yet:

- packet framing and binary codec
- key exchange and encryption
- message authentication and rekeying
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

## Suggested implementation order

1. transport packet reader/writer and protocol banner exchange
2. key exchange and host-key verification
3. user authentication service
4. channel multiplexer and session channels
5. exec and shell requests with PTY support
6. SFTP subsystem
7. local, remote, and dynamic port forwarding
