import '../transport/host_key.dart';
import '../transport/transport.dart';

class SshClientConfig {
  const SshClientConfig({
    required this.host,
    required this.username,
    this.port = 22,
    this.transport = const SshTransportSettings(),
    this.hostKeyVerifier,
  });

  final String host;
  final int port;
  final String username;
  final SshTransportSettings transport;
  final SshHostKeyVerifier? hostKeyVerifier;

  SshEndpoint get endpoint => SshEndpoint(host: host, port: port);
}

enum SshClientState { idle, connecting, connected, closing, closed }
