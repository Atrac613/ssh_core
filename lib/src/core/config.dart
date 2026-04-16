import '../transport/transport.dart';

class SshClientConfig {
  const SshClientConfig({
    required this.host,
    required this.username,
    this.port = 22,
    this.transport = const SshTransportSettings(),
  });

  final String host;
  final int port;
  final String username;
  final SshTransportSettings transport;

  SshEndpoint get endpoint => SshEndpoint(host: host, port: port);
}

enum SshClientState { idle, connecting, connected, closing, closed }
