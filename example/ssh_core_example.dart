import 'dart:convert';

import 'package:ssh_core/ssh_core.dart';

Future<void> main() async {
  final client = SshClient(
    config: const SshClientConfig(host: 'example.com', username: 'demo'),
    authMethods: const <SshAuthMethod>[
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
  final SshBannerExchange _bannerExchange = const SshBannerExchange();
  final SshLineReader _lineReader = SshLineReader();

  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    _lineReader.add(
      utf8.encode('demo prelude line\r\nSSH-2.0-demo-server example\r\n'),
    );

    final List<String> remoteLines = <String>[];
    for (;;) {
      final String? line = _lineReader.readLine();
      if (line == null) {
        break;
      }
      remoteLines.add(line);
    }

    final SshBannerExchangeResult exchange = _bannerExchange.resolve(
      localIdentification: settings.clientIdentification,
      remoteLines: remoteLines,
    );

    return SshHandshakeInfo.fromBannerExchange(
      exchange,
      negotiatedAlgorithms: const <String, String>{
        'kex': 'curve25519-sha256',
        'cipher': 'chacha20-poly1305@openssh.com',
      },
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
