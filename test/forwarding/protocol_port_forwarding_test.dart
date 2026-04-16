import 'package:ssh_core/ssh_core.dart';
import 'package:test/test.dart';

void main() {
  test('uses assigned remote ports from request-success replies', () async {
    final _ReplyingTransport transport = _ReplyingTransport(
      replies: <SshGlobalRequestReply>[
        SshGlobalRequestReply.success(
          responseData: (SshPayloadWriter()..writeUint32(4100)).toBytes(),
        ),
        SshGlobalRequestReply.success(),
      ],
    );
    final SshProtocolPortForwardingService service =
        SshProtocolPortForwardingService(transport: transport);

    final SshPortForward forward = await service.openForward(
      const SshForwardRequest.remote(
        bindHost: '127.0.0.1',
        bindPort: 0,
        target: SshForwardTarget(host: '127.0.0.1', port: 22),
      ),
    );

    expect(forward.bindPort, 4100);
    expect(transport.sentRequests.first.type, sshTcpIpForwardRequestName);

    await forward.close();

    final SshCancelTcpIpForwardRequest cancelRequest =
        SshCancelTcpIpForwardRequest.decode(
      transport.sentRequests.last.payload['encodedPayload']! as List<int>,
    );
    expect(cancelRequest.bindPort, 4100);
  });

  test('rejects bindPort=0 when request replies are unavailable', () async {
    final SshProtocolPortForwardingService service =
        SshProtocolPortForwardingService(transport: _LegacyTransport());

    await expectLater(
      () => service.openForward(
        const SshForwardRequest.remote(
          bindHost: '127.0.0.1',
          bindPort: 0,
          target: SshForwardTarget(host: '127.0.0.1', port: 22),
        ),
      ),
      throwsA(isA<SshPortForwardingException>()),
    );
  });
}

class _ReplyingTransport implements SshGlobalRequestReplyTransport {
  _ReplyingTransport({required List<SshGlobalRequestReply> replies})
      : _replies = List<SshGlobalRequestReply>.from(replies);

  final List<SshGlobalRequestReply> _replies;
  final List<SshGlobalRequest> sentRequests = <SshGlobalRequest>[];

  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    return const SshHandshakeInfo(
      localIdentification: 'SSH-2.0-test-client',
      remoteIdentification: 'SSH-2.0-test-server',
    );
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {
    sentRequests.add(request);
  }

  @override
  Future<SshGlobalRequestReply> sendGlobalRequestWithReply(
    SshGlobalRequest request,
  ) async {
    sentRequests.add(request);
    return _replies.removeAt(0);
  }
}

class _LegacyTransport implements SshTransport {
  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    return const SshHandshakeInfo(
      localIdentification: 'SSH-2.0-test-client',
      remoteIdentification: 'SSH-2.0-test-server',
    );
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}
}
