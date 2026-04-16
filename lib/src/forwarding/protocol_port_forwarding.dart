import '../transport/message_codec.dart';
import '../transport/transport.dart';
import 'port_forwarding.dart';
import 'protocol.dart';

class SshPortForwardingException implements Exception {
  const SshPortForwardingException(this.message);

  final String message;

  @override
  String toString() => 'SshPortForwardingException($message)';
}

class SshProtocolPortForwardingService implements SshPortForwardingService {
  const SshProtocolPortForwardingService({required this.transport});

  final SshTransport transport;

  @override
  Future<SshPortForward> openForward(SshForwardRequest request) async {
    switch (request.mode) {
      case SshForwardingMode.remote:
        final SshGlobalRequest requestMessage = SshGlobalRequest(
          type: sshTcpIpForwardRequestName,
          wantReply: true,
          payload: <String, Object?>{
            'encodedPayload': SshTcpIpForwardRequest(
              bindHost: request.bindHost,
              bindPort: request.bindPort,
            ).encode(),
          },
        );
        int resolvedBindPort = request.bindPort;
        if (transport is SshGlobalRequestReplyTransport) {
          final SshGlobalRequestReply reply =
              await (transport as SshGlobalRequestReplyTransport)
                  .sendGlobalRequestWithReply(requestMessage);
          if (!reply.isSuccess) {
            throw const SshPortForwardingException(
              'SSH remote port forwarding request was rejected.',
            );
          }

          if (request.bindPort == 0) {
            final SshPayloadReader reader =
                SshPayloadReader(reply.responseData);
            resolvedBindPort = reader.readUint32();
            reader.expectDone();
          }
        } else {
          if (request.bindPort == 0) {
            throw const SshPortForwardingException(
              'Remote forwarding with bindPort=0 requires request replies.',
            );
          }
          await transport.sendGlobalRequest(requestMessage);
        }

        return _SshProtocolPortForward(
          transport: transport,
          mode: request.mode,
          bindHost: request.bindHost,
          bindPort: resolvedBindPort,
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
