import 'dart:convert';

import 'package:ssh_core/ssh_core.dart';

Future<void> main() async {
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

class _FakeTransport implements SshTransport {
  SshTransportState _state = SshTransportState.disconnected;

  @override
  SshTransportState get state => _state;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    _state = SshTransportState.connected;
    return SshHandshakeInfo(
      localIdentification: settings.clientIdentification,
      remoteIdentification: 'SSH-2.0-fake',
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
