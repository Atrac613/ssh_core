import 'dart:convert';

import 'package:ssh_core/ssh_core.dart';

Future<void> main() async {
  final SshHostKey trustedHostKey = _demoHostKey();
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
  final forward = await client.forwardLocal(
    bindHost: '127.0.0.1',
    bindPort: 8022,
    targetHost: '127.0.0.1',
    targetPort: 22,
  );
  await forward.close();
  await client.close();
}

class DemoTransport implements SshTransport {
  DemoTransport({required SshHostKey hostKey}) : _hostKey = hostKey;

  final SshBannerExchange _bannerExchange = const SshBannerExchange();
  final SshAlgorithmNegotiator _algorithmNegotiator =
      const SshAlgorithmNegotiator();
  final SshHostKey _hostKey;

  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    final SshKexInitMessage clientProposal = SshKexInitMessage(
      cookie: List<int>.filled(16, 1),
      kexAlgorithms: const <String>[
        'curve25519-sha256',
        'diffie-hellman-group14-sha256',
      ],
      serverHostKeyAlgorithms: const <String>['ssh-ed25519', 'rsa-sha2-256'],
      encryptionAlgorithmsClientToServer: const <String>[
        'chacha20-poly1305@openssh.com',
      ],
      encryptionAlgorithmsServerToClient: const <String>[
        'chacha20-poly1305@openssh.com',
      ],
      macAlgorithmsClientToServer: const <String>['hmac-sha2-256'],
      macAlgorithmsServerToClient: const <String>['hmac-sha2-256'],
      compressionAlgorithmsClientToServer: const <String>['none'],
      compressionAlgorithmsServerToClient: const <String>['none'],
    );
    final SshKexInitMessage serverProposal = SshKexInitMessage(
      cookie: List<int>.filled(16, 2),
      kexAlgorithms: const <String>['curve25519-sha256'],
      serverHostKeyAlgorithms: const <String>['ssh-ed25519'],
      encryptionAlgorithmsClientToServer: const <String>[
        'chacha20-poly1305@openssh.com',
      ],
      encryptionAlgorithmsServerToClient: const <String>[
        'chacha20-poly1305@openssh.com',
      ],
      macAlgorithmsClientToServer: const <String>['hmac-sha2-256'],
      macAlgorithmsServerToClient: const <String>['hmac-sha2-256'],
      compressionAlgorithmsClientToServer: const <String>['none'],
      compressionAlgorithmsServerToClient: const <String>['none'],
    );
    final SshTransportStream transportStream = SshTransportStream(
      incoming: Stream<List<int>>.fromIterable(<List<int>>[
        utf8.encode('demo prelude line\r\nSSH-2.0-demo-server example\r\n'),
      ]),
      onWrite: (List<int> bytes) {},
      bannerExchange: _bannerExchange,
    );

    final SshBannerExchangeResult exchange =
        await transportStream.exchangeBanners(
      localIdentification: settings.clientIdentification,
    );
    final SshNegotiatedAlgorithms algorithms = _algorithmNegotiator.negotiate(
      clientProposal: clientProposal,
      serverProposal: serverProposal,
    );
    final SshKexEcdhInitMessage clientKeyExchange = SshKexEcdhInitMessage(
      clientEphemeralPublicKey: const <int>[3, 1, 4, 1, 5],
    );
    final SshSignature exchangeHashSignature = SshSignature(
      algorithm: 'ssh-ed25519',
      blob: const <int>[3, 5, 8, 9],
    );
    final SshKexEcdhReplyMessage serverKeyExchange = SshKexEcdhReplyMessage(
      hostKey: _hostKey,
      serverEphemeralPublicKey: const <int>[9, 2, 6, 5],
      exchangeHashSignature: exchangeHashSignature.encode(),
    );
    assert(
      SshKexEcdhExchangeHashInput(
        clientIdentification: exchange.localBanner.value,
        serverIdentification: exchange.remoteBanner.value,
        clientKexInitPayload: clientProposal.encodePayload(),
        serverKexInitPayload: serverProposal.encodePayload(),
        hostKey: serverKeyExchange.hostKey,
        clientEphemeralPublicKey: clientKeyExchange.clientEphemeralPublicKey,
        serverEphemeralPublicKey: serverKeyExchange.serverEphemeralPublicKey,
        sharedSecret: BigInt.from(42),
      ).encode().isNotEmpty,
    );

    return SshHandshakeInfo.fromBannerExchange(
      exchange,
      negotiatedAlgorithms: algorithms.asHandshakeMap(),
      hostKey: _hostKey,
    );
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}
}

class DemoAuthenticator implements SshAuthenticator {
  @override
  Future<SshAuthResult> authenticate({
    required SshAuthContext context,
    required List<SshAuthMethod> methods,
  }) async {
    if (methods.isEmpty) {
      return const SshAuthResult.failure(
        message: 'At least one auth method is required.',
      );
    }
    return const SshAuthResult.success(message: 'Authenticated.');
  }
}

class DemoChannel implements SshChannel {
  @override
  int get id => 1;

  @override
  SshChannelType get type => SshChannelType.session;

  @override
  Future<void> close() async {}

  @override
  Future<void> sendRequest(SshChannelRequest request) async {}
}

class DemoChannelFactory implements SshChannelFactory {
  @override
  Future<SshChannel> openChannel(SshChannelOpenRequest request) async {
    return DemoChannel();
  }
}

class DemoShellSession implements SshShellSession {
  DemoShellSession(this.channel);

  @override
  final SshChannel channel;

  @override
  SshSessionState get state => SshSessionState.active;

  @override
  Stream<List<int>> get stderr => const Stream<List<int>>.empty();

  @override
  Stream<List<int>> get stdout => const Stream<List<int>>.empty();

  @override
  Future<void> close() async {}

  @override
  Future<void> resizePty(SshPtyConfig nextPty) async {}

  @override
  Future<void> writeStdin(List<int> data) async {}
}

class DemoSessionManager implements SshSessionManager {
  @override
  Future<SshShellSession> openShellSession(SshShellRequest request) async {
    return DemoShellSession(DemoChannel());
  }
}

class DemoExecService implements SshExecService {
  final SshPacketCodec _packetCodec = const SshPacketCodec();

  @override
  Future<SshExecResult> exec(SshExecRequest request) async {
    final SshBinaryPacket packet = _packetCodec.decode(
      _packetCodec.encode(utf8.encode(request.command)),
    );

    return SshExecResult(
      exitCode: 0,
      stdout: utf8.encode('demo:${utf8.decode(packet.payload)}\n'),
    );
  }
}

class DemoSftpClient implements SftpClient {
  @override
  Future<void> close() async {}

  @override
  Future<void> createDirectory(String path, {bool recursive = false}) async {}

  @override
  Future<void> delete(String path, {bool recursive = false}) async {}

  @override
  Future<List<SftpFileEntry>> listDirectory(String path) async {
    return const <SftpFileEntry>[
      SftpFileEntry(path: '/tmp/demo.txt', type: SftpFileType.file, size: 4),
    ];
  }

  @override
  Future<List<int>> readFile(String path) async {
    return utf8.encode('demo');
  }

  @override
  Future<void> writeFile(String path, List<int> bytes) async {}
}

class DemoSftpSubsystem implements SftpSubsystem {
  @override
  Future<SftpClient> open() async {
    return DemoSftpClient();
  }
}

class DemoPortForward implements SshPortForward {
  const DemoPortForward({
    required this.mode,
    required this.bindHost,
    required this.bindPort,
  });

  @override
  final SshForwardingMode mode;

  @override
  final String bindHost;

  @override
  final int bindPort;

  @override
  Future<void> close() async {}
}

class DemoPortForwardingService implements SshPortForwardingService {
  @override
  Future<SshPortForward> openForward(SshForwardRequest request) async {
    return DemoPortForward(
      mode: request.mode,
      bindHost: request.bindHost,
      bindPort: request.bindPort,
    );
  }
}

SshHostKey _demoHostKey() {
  final SshPayloadWriter writer = SshPayloadWriter()
    ..writeString('ssh-ed25519')
    ..writeStringBytes(const <int>[1, 2, 3, 4, 5, 6]);
  return SshHostKey.decode(writer.toBytes());
}
