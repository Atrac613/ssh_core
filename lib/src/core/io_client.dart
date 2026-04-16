import '../auth/auth.dart';
import '../auth/protocol_authenticator.dart';
import '../channels/packet_channel.dart';
import '../exec/protocol_exec_service.dart';
import '../forwarding/io_port_forwarding.dart';
import '../sessions/protocol_session_manager.dart';
import '../sftp/protocol_sftp.dart';
import '../transport/secure_socket_transport.dart';
import 'client.dart';
import 'config.dart';

class SshIoClientFactory {
  const SshIoClientFactory._();

  static SshClient create({
    required SshClientConfig config,
    required List<SshAuthMethod> authMethods,
    SshSecureSocketTransport? transport,
    SshUserAuthProtocolAuthenticator authenticator =
        const SshUserAuthProtocolAuthenticator(),
    int sftpProtocolVersion = 3,
  }) {
    final SshSecureSocketTransport resolvedTransport =
        transport ?? SshSecureSocketTransport();
    final SshPacketChannelFactory channelFactory = SshPacketChannelFactory(
      transport: resolvedTransport,
    );

    return SshClient(
      config: config,
      authMethods: authMethods,
      transport: resolvedTransport,
      authenticator: authenticator,
      channelFactory: channelFactory,
      sessionManager: SshProtocolSessionManager(channelFactory: channelFactory),
      execService: SshProtocolExecService(channelFactory: channelFactory),
      sftpSubsystem: SshProtocolSftpSubsystem(
        channelFactory: channelFactory,
        protocolVersion: sftpProtocolVersion,
      ),
      portForwardingService: SshIoPortForwardingService(
        transport: resolvedTransport,
        channelFactory: channelFactory,
      ),
    );
  }
}
