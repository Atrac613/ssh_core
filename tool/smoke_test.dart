import 'dart:convert';
import 'dart:typed_data';

import 'package:ssh_core/ssh_core.dart';

Future<void> main() async {
  await _exerciseTransportPrimitives();

  final client = SshClient(
    config: const SshClientConfig(host: 'localhost', username: 'tester'),
    authMethods: const <SshAuthMethod>[SshPasswordAuthMethod(password: 'pw')],
    transport: _FakeTransport(),
    authenticator: _FakeAuthenticator(),
    channelFactory: _FakeChannelFactory(),
    sessionManager: _FakeSessionManager(),
    execService: _FakeExecService(),
    sftpSubsystem: _FakeSftpSubsystem(),
    portForwardingService: _FakePortForwardingService(),
  );

  assert(client.state == SshClientState.idle);

  await client.connect();
  assert(client.isConnected);

  final execResult = await client.exec('echo smoke');
  assert(execResult.exitCode == 0);
  assert(execResult.stdoutText.trim() == 'ok:echo smoke');

  final shell = await client.openShell(
    pty: const SshPtyConfig(columns: 120, rows: 40),
  );
  assert(shell.state == SshSessionState.active);

  final sftp = await client.openSftp();
  final files = await sftp.listDirectory('/tmp');
  assert(files.single.path == '/tmp/demo.txt');

  final localForward = await client.forwardLocal(
    bindHost: '127.0.0.1',
    bindPort: 10022,
    targetHost: '127.0.0.1',
    targetPort: 22,
  );
  assert(localForward.mode == SshForwardingMode.local);

  await localForward.close();
  await sftp.close();
  await shell.close();
  await client.close();

  assert(client.state == SshClientState.closed);
}

Future<void> _exerciseTransportPrimitives() async {
  final SshPacketCodec codec = SshPacketCodec(
    paddingBytesFactory: (int length) =>
        List<int>.generate(length, (int i) => i),
  );
  final SshTransportBuffer transportBuffer = SshTransportBuffer(
    packetCodec: codec,
  );
  transportBuffer.add(
    utf8.encode(
        'prelude one\r\nprelude two\r\nSSH-2.0-demo-server integration\r\n'),
  );

  final List<String> remoteLines = <String>[];
  for (;;) {
    final String? line = transportBuffer.readLine();
    if (line == null) {
      break;
    }
    remoteLines.add(line);
  }

  assert(remoteLines.length == 3);
  assert(transportBuffer.pendingByteCount == 0);

  final SshBannerExchange bannerExchange = const SshBannerExchange();
  final SshBannerExchangeResult exchange = bannerExchange.resolve(
    localIdentification: 'SSH-2.0-ssh_core-test',
    remoteLines: remoteLines,
  );

  assert(exchange.localBanner.protocolVersion == '2.0');
  assert(exchange.remoteBanner.softwareVersion == 'demo-server');
  assert(exchange.ignoredLines.length == 2);
  assert(
    bannerExchange.formatLocalLine('SSH-2.0-ssh_core-test') ==
        'SSH-2.0-ssh_core-test\r\n',
  );

  final Uint8List frame = codec.encode(<int>[94, 1, 2, 3]);

  transportBuffer.add(frame.sublist(0, 3));
  assert(transportBuffer.readPacket() == null);
  transportBuffer.add(frame.sublist(3));

  final SshBinaryPacket? packet = transportBuffer.readPacket();
  assert(packet != null);
  final SshBinaryPacket decodedPacket = packet!;
  assert(decodedPacket.messageId == 94);
  assert(decodedPacket.payload.length == 4);
  assert(decodedPacket.padding.length >= 4);
  assert(transportBuffer.pendingByteCount == 0);

  final List<List<int>> outboundWrites = <List<int>>[];
  final SshTransportStream transportStream = SshTransportStream(
    incoming: Stream<List<int>>.fromIterable(<List<int>>[
      utf8.encode('prelude one\r\nSSH-2.0-demo-server integration\r\n'),
      frame.sublist(0, 3),
      frame.sublist(3),
    ]),
    onWrite: (List<int> bytes) {
      outboundWrites.add(List<int>.from(bytes));
    },
    bannerExchange: bannerExchange,
    packetCodec: codec,
  );

  final SshBannerExchangeResult streamedExchange =
      await transportStream.exchangeBanners(
    localIdentification: 'SSH-2.0-ssh_core-test',
  );
  assert(streamedExchange.remoteBanner.softwareVersion == 'demo-server');
  assert(
    utf8.decode(outboundWrites.single) == 'SSH-2.0-ssh_core-test\r\n',
  );

  final SshBinaryPacket streamedPacket = await transportStream.readPacket();
  assert(streamedPacket.messageId == 94);
  assert(streamedPacket.payload.length == 4);
  assert(transportStream.pendingByteCount == 0);
  await transportStream.close();
}

class _FakeTransport implements SshTransport {
  SshTransportState _state = SshTransportState.disconnected;
  final SshBannerExchange _bannerExchange = const SshBannerExchange();

  @override
  SshTransportState get state => _state;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    _state = SshTransportState.connected;
    final SshTransportStream transportStream = SshTransportStream(
      incoming: Stream<List<int>>.fromIterable(<List<int>>[
        utf8.encode('fake daemon boot message\r\nSSH-2.0-fake\r\n'),
      ]),
      onWrite: (List<int> bytes) {},
      bannerExchange: _bannerExchange,
    );

    final SshBannerExchangeResult exchange =
        await transportStream.exchangeBanners(
      localIdentification: settings.clientIdentification,
    );

    return SshHandshakeInfo.fromBannerExchange(
      exchange,
      negotiatedAlgorithms: const <String, String>{'kex': 'curve25519-sha256'},
    );
  }

  @override
  Future<void> disconnect() async {
    _state = SshTransportState.closed;
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}
}

class _FakeAuthenticator implements SshAuthenticator {
  @override
  Future<SshAuthResult> authenticate({
    required SshAuthContext context,
    required List<SshAuthMethod> methods,
  }) async {
    return methods.isEmpty
        ? const SshAuthResult.failure(message: 'Missing auth methods.')
        : const SshAuthResult.success();
  }
}

class _FakeChannel implements SshChannel {
  @override
  int get id => 1;

  @override
  SshChannelType get type => SshChannelType.session;

  @override
  Future<void> close() async {}

  @override
  Future<void> sendRequest(SshChannelRequest request) async {}
}

class _FakeChannelFactory implements SshChannelFactory {
  @override
  Future<SshChannel> openChannel(SshChannelOpenRequest request) async {
    return _FakeChannel();
  }
}

class _FakeShellSession implements SshShellSession {
  _FakeShellSession(this.channel);

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

class _FakeSessionManager implements SshSessionManager {
  @override
  Future<SshShellSession> openShellSession(SshShellRequest request) async {
    return _FakeShellSession(_FakeChannel());
  }
}

class _FakeExecService implements SshExecService {
  @override
  Future<SshExecResult> exec(SshExecRequest request) async {
    return SshExecResult(
      exitCode: 0,
      stdout: utf8.encode('ok:${request.command}\n'),
    );
  }
}

class _FakeSftpClient implements SftpClient {
  @override
  Future<void> close() async {}

  @override
  Future<void> createDirectory(String path, {bool recursive = false}) async {}

  @override
  Future<void> delete(String path, {bool recursive = false}) async {}

  @override
  Future<List<SftpFileEntry>> listDirectory(String path) async {
    return const <SftpFileEntry>[
      SftpFileEntry(path: '/tmp/demo.txt', type: SftpFileType.file),
    ];
  }

  @override
  Future<List<int>> readFile(String path) async {
    return utf8.encode('demo');
  }

  @override
  Future<void> writeFile(String path, List<int> bytes) async {}
}

class _FakeSftpSubsystem implements SftpSubsystem {
  @override
  Future<SftpClient> open() async {
    return _FakeSftpClient();
  }
}

class _FakePortForward implements SshPortForward {
  const _FakePortForward({
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

class _FakePortForwardingService implements SshPortForwardingService {
  @override
  Future<SshPortForward> openForward(SshForwardRequest request) async {
    return _FakePortForward(
      mode: request.mode,
      bindHost: request.bindHost,
      bindPort: request.bindPort,
    );
  }
}
