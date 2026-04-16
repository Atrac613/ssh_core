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
- auth service and userauth packet helpers for protocol flows
- protocol authenticator for `none`, `password`, `publickey`, and keyboard-interactive
- channel packet helpers for open/data/request/window/close flows
- packet-backed channel factory for open/request/data/close handling
- packet-backed shell session manager and exec service
- session and exec channel-request helpers including PTY/env/exit messages
- SFTP packet helpers for init/version/open/read/write/status/name flows
- packet-backed SFTP subsystem for list/read/write/mkdir/delete flows
- forwarding packet helpers for `tcpip-forward` and TCP/IP channel payloads
- SOCKS5 helpers for dynamic port-forward request and reply parsing
- IO-backed local, remote, and dynamic port forwarding bridges
- remote port-forward control service built on SSH global requests
- transport payload/message codec and `SSH_MSG_KEXINIT` helper
- transport global-request helpers for forwarding-related flows
- transport algorithm negotiation for client/server `KEXINIT` proposals
- host key parsing and verifier contracts for the pre-auth handshake
- ECDH key exchange message and exchange-hash input helpers
- SSH signature blob helper for KEX reply parsing
- `SSH_MSG_NEWKEYS` helper for the end of key exchange
- transport banner parsing/exchange helpers and binary packet framing helpers
- secure socket transport with Curve25519 key exchange, Ed25519 host-key
  verification, `aes*-ctr` packet encryption, and `hmac-sha2-256`
- `SshIoClientFactory` for wiring a live `SshClient` with protocol services
- a smoke test that exercises the package with fake implementations
- example wiring showing how a concrete implementation can plug into the stack

Not implemented yet:

- rekeying after the initial key exchange
- compression algorithms other than `none`
- broader host-key, cipher, and MAC algorithm coverage
- remote forwarding with auto-assigned remote ports and advanced forwarding
  variants

## Public modules

- `transport`: socket lifecycle, handshake metadata, and global requests
- `auth`: authentication strategies, auth results, and userauth packet helpers
- `channels`: generic channel lifecycle and channel packet helpers
- `sessions`: shell/session abstractions and session channel-request helpers
- `pty`: terminal allocation and resize metadata
- `exec`: non-interactive command execution
- `sftp`: file transfer subsystem contracts and packet helpers
- `port forwarding`: local, remote, and dynamic forwarding contracts and packet helpers

## Example

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
        trustedKeys: [
          SshTrustedHostKey(host: 'example.com', hostKey: trustedHostKey),
        ],
      ),
    ),
    authMethods: const [
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

See `example/ssh_core_example.dart` for a complete compiling example.

## Transport Primitives

The transport module now includes low-level helpers for the earliest SSH
handshake steps:

- `SshTransportBanner` and `SshBannerExchange` for SSH identification strings
- `SshTransportBuffer` for mixed line and packet reads from one byte stream
- `SshTransportStream` for async banner and packet I/O over byte streams
- `SshPacketTransport` for modules that need packet-level SSH access
- `SshSocketTransport` in `package:ssh_core/ssh_core_io.dart`
- `SshPayloadWriter`, `SshPayloadReader`, `mpint`, and `SshKexInitMessage`
- `SshHostKey`, `SshHostKeyVerifier`, and `SshStaticHostKeyVerifier`
- `SshSignature`, `SshAlgorithmNegotiator`, `SshNegotiatedAlgorithms`, and KEX helpers
- `SshLineReader` for chunked banner line parsing from socket bytes
- `SshPacketCodec` for SSH binary packet framing
- `SshPacketReader` for reading framed packets from chunked byte streams

For `dart:io` environments, `package:ssh_core/ssh_core_io.dart` now exposes:

- `SshSocketTransport` for banner exchange and plain packet I/O primitives
- `SshSecureSocketTransport` for the initial secure handshake and encrypted
  packet transport
- `SshIoClientFactory` for building a live `SshClient` with protocol-backed
  auth, channels, shell/exec, SFTP, and forwarding services

## Suggested implementation order

1. transport socket integration around packet codec and banner exchange
2. key exchange and host-key verification
3. user authentication service
4. channel multiplexer and session channels
5. exec and shell requests with PTY support
6. SFTP subsystem
7. local, remote, and dynamic port forwarding
