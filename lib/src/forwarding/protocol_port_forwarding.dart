import '../transport/transport.dart';
import 'port_forwarding.dart';
import 'protocol.dart';

class SshProtocolPortForwardingService implements SshPortForwardingService {
  const SshProtocolPortForwardingService({required this.transport});

  final SshTransport transport;

  @override
  Future<SshPortForward> openForward(SshForwardRequest request) async {
    switch (request.mode) {
      case SshForwardingMode.remote:
        await transport.sendGlobalRequest(
          SshGlobalRequest(
            type: sshTcpIpForwardRequestName,
            wantReply: true,
            payload: <String, Object?>{
              'encodedPayload': SshTcpIpForwardRequest(
                bindHost: request.bindHost,
                bindPort: request.bindPort,
              ).encode(),
            },
          ),
        );
        return _SshProtocolPortForward(
          transport: transport,
          mode: request.mode,
          bindHost: request.bindHost,
          bindPort: request.bindPort,
        );
      case SshForwardingMode.local:
        throw UnsupportedError(
          'Local forwarding requires an IO-backed listener implementation.',
        );
      case SshForwardingMode.dynamic:
        throw UnsupportedError(
          'Dynamic forwarding requires an IO-backed SOCKS listener implementation.',
        );
    }
  }
}

class _SshProtocolPortForward implements SshPortForward {
  _SshProtocolPortForward({
    required SshTransport transport,
    required this.mode,
    required this.bindHost,
    required this.bindPort,
  }) : _transport = transport;

  final SshTransport _transport;
  bool _closed = false;

  @override
  final SshForwardingMode mode;

  @override
  final String bindHost;

  @override
  final int bindPort;

  @override
  Future<void> close() async {
    if (_closed) {
      return;
    }

    _closed = true;
    await _transport.sendGlobalRequest(
      SshGlobalRequest(
        type: sshCancelTcpIpForwardRequestName,
        wantReply: true,
        payload: <String, Object?>{
          'encodedPayload': SshCancelTcpIpForwardRequest(
            bindHost: bindHost,
            bindPort: bindPort,
          ).encode(),
        },
      ),
    );
  }
}
