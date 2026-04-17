import 'dart:async';

import 'package:ssh_core/ssh_core.dart';
import 'package:test/test.dart';

void main() {
  group('SshClient.connect', () {
    test(
      'disconnects the transport when host key verification fails',
      () async {
        final _FakeTransport transport = _FakeTransport(
          handshake: SshHandshakeInfo(
            localIdentification: 'SSH-2.0-shellway',
            remoteIdentification: 'SSH-2.0-test',
            hostKey: _testHostKey(),
          ),
        );
        final SshClient client = _createClient(
          transport: transport,
          hostKeyVerifier: const SshCallbackHostKeyVerifier(
            _rejectHostKeyVerification,
          ),
        );

        await expectLater(
          client.connect(),
          throwsA(isA<SshHostKeyException>()),
        );

        expect(client.state, SshClientState.idle);
        expect(transport.disconnectCallCount, 1);
        expect(transport.state, SshTransportState.closed);
      },
    );

    test('disconnects the transport when authentication fails', () async {
      final _FakeTransport transport = _FakeTransport(
        handshake: SshHandshakeInfo(
          localIdentification: 'SSH-2.0-shellway',
          remoteIdentification: 'SSH-2.0-test',
          hostKey: _testHostKey(),
        ),
      );
      final SshClient client = _createClient(
        transport: transport,
        hostKeyVerifier: const SshAllowAnyHostKeyVerifier(),
        authenticator: const _FakeAuthenticator(
          result: SshAuthResult.failure(message: 'bad password'),
        ),
      );

      await expectLater(client.connect(), throwsA(isA<SshAuthException>()));

      expect(client.state, SshClientState.idle);
      expect(transport.disconnectCallCount, 1);
      expect(transport.state, SshTransportState.closed);
    });

    test(
      'keeps the transport connected after a successful connection',
      () async {
        final _FakeTransport transport = _FakeTransport(
          handshake: SshHandshakeInfo(
            localIdentification: 'SSH-2.0-shellway',
            remoteIdentification: 'SSH-2.0-test',
            hostKey: _testHostKey(),
          ),
        );
        final SshClient client = _createClient(
          transport: transport,
          hostKeyVerifier: const SshAllowAnyHostKeyVerifier(),
        );

        await client.connect();

        expect(client.state, SshClientState.connected);
        expect(transport.disconnectCallCount, 0);
        expect(transport.state, SshTransportState.connected);
      },
    );
  });

  group('host key helpers', () {
    test('exposes a SHA-256 fingerprint', () {
      final SshHostKey hostKey = _testHostKey();

      expect(
        hostKey.sha256Fingerprint,
        'SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4',
      );
    });

    test('supports callback-based host key verification', () async {
      final SshHostKey hostKey = _testHostKey();
      late final SshHostKeyVerificationContext capturedContext;
      final SshHostKeyVerifier verifier = SshCallbackHostKeyVerifier((
        SshHostKeyVerificationContext context,
      ) async {
        capturedContext = context;
        return const SshHostKeyVerificationResult.success(message: 'trusted');
      });

      final SshHostKeyVerificationResult result = await verifier.verify(
        SshHostKeyVerificationContext(
          host: 'example.com',
          port: 22,
          localIdentification: 'SSH-2.0-shellway',
          remoteIdentification: 'SSH-2.0-test',
          hostKey: hostKey,
        ),
      );

      expect(result.isSuccess, isTrue);
      expect(capturedContext.host, 'example.com');
      expect(
        capturedContext.hostKey.sha256Fingerprint,
        hostKey.sha256Fingerprint,
      );
    });
  });
}

SshHostKeyVerificationResult _rejectHostKeyVerification(
  SshHostKeyVerificationContext context,
) {
  return const SshHostKeyVerificationResult.failure(message: 'untrusted');
}

SshClient _createClient({
  required _FakeTransport transport,
  required SshHostKeyVerifier hostKeyVerifier,
  SshAuthenticator authenticator = const _FakeAuthenticator(),
}) {
  return SshClient(
    config: SshClientConfig(
      host: 'example.com',
      username: 'demo',
      hostKeyVerifier: hostKeyVerifier,
    ),
    authMethods: const <SshAuthMethod>[SshPasswordAuthMethod(password: 'pw')],
    transport: transport,
    authenticator: authenticator,
    channelFactory: const _UnsupportedChannelFactory(),
    sessionManager: const _UnsupportedSessionManager(),
    execService: const _UnsupportedExecService(),
    sftpSubsystem: const _UnsupportedSftpSubsystem(),
    portForwardingService: const _UnsupportedPortForwardingService(),
  );
}

SshHostKey _testHostKey() {
  return SshHostKey.decode(
    (SshPayloadWriter()
          ..writeString('ssh-ed25519')
          ..writeStringBytes(List<int>.generate(32, (int index) => index + 1)))
        .toBytes(),
  );
}

class _FakeTransport implements SshTransport {
  _FakeTransport({required this.handshake});

  final SshHandshakeInfo handshake;
  int disconnectCallCount = 0;
  SshTransportState _state = SshTransportState.disconnected;

  @override
  SshTransportState get state => _state;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    _state = SshTransportState.connected;
    return handshake;
  }

  @override
  Future<void> disconnect() async {
    disconnectCallCount += 1;
    _state = SshTransportState.closed;
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}
}

class _FakeAuthenticator implements SshAuthenticator {
  const _FakeAuthenticator({
    this.result = const SshAuthResult.success(message: 'ok'),
  });

  final SshAuthResult result;

  @override
  Future<SshAuthResult> authenticate({
    required SshAuthContext context,
    required List<SshAuthMethod> methods,
  }) async {
    return result;
  }
}

class _UnsupportedChannelFactory implements SshChannelFactory {
  const _UnsupportedChannelFactory();

  @override
  Future<SshChannel> openChannel(SshChannelOpenRequest request) {
    throw UnimplementedError();
  }
}

class _UnsupportedSessionManager implements SshSessionManager {
  const _UnsupportedSessionManager();

  @override
  Future<SshShellSession> openShellSession(SshShellRequest request) {
    throw UnimplementedError();
  }
}

class _UnsupportedExecService implements SshExecService {
  const _UnsupportedExecService();

  @override
  Future<SshExecResult> exec(SshExecRequest request) {
    throw UnimplementedError();
  }
}

class _UnsupportedSftpSubsystem implements SftpSubsystem {
  const _UnsupportedSftpSubsystem();

  @override
  Future<SftpClient> open() {
    throw UnimplementedError();
  }
}

class _UnsupportedPortForwardingService implements SshPortForwardingService {
  const _UnsupportedPortForwardingService();

  @override
  Future<SshPortForward> openForward(SshForwardRequest request) {
    throw UnimplementedError();
  }
}
