class SshEndpoint {
  const SshEndpoint({required this.host, this.port = 22});

  final String host;
  final int port;
}

class SshTransportSettings {
  const SshTransportSettings({
    this.connectTimeout = const Duration(seconds: 10),
    this.keepAliveInterval,
    this.clientIdentification = 'SSH-2.0-ssh_core',
  });

  final Duration connectTimeout;
  final Duration? keepAliveInterval;
  final String clientIdentification;
}

enum SshTransportState { disconnected, connecting, connected, closed }

class SshHandshakeInfo {
  const SshHandshakeInfo({
    required this.localIdentification,
    required this.remoteIdentification,
    this.negotiatedAlgorithms = const <String, String>{},
  });

  final String localIdentification;
  final String remoteIdentification;
  final Map<String, String> negotiatedAlgorithms;
}

class SshGlobalRequest {
  const SshGlobalRequest({
    required this.type,
    this.wantReply = false,
    this.payload = const <String, Object?>{},
  });

  final String type;
  final bool wantReply;
  final Map<String, Object?> payload;
}

abstract class SshTransport {
  SshTransportState get state;

  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  });

  Future<void> sendGlobalRequest(SshGlobalRequest request);

  Future<void> disconnect();
}
