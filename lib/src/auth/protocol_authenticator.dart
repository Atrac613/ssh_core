import '../core/exceptions.dart';
import '../transport/transport.dart';
import 'auth.dart';
import 'protocol.dart';

class SshUserAuthProtocolAuthenticator implements SshAuthenticator {
  const SshUserAuthProtocolAuthenticator({
    this.serviceName = sshConnectionService,
    this.userauthServiceName = sshUserauthService,
  });

  final String serviceName;
  final String userauthServiceName;

  @override
  Future<SshAuthResult> authenticate({
    required SshAuthContext context,
    required List<SshAuthMethod> methods,
  }) async {
    final SshPacketTransport transport = _requirePacketTransport(
      context.transport,
    );
    await _requestUserauthService(transport);

    List<String> allowedMethods = const <String>[];
    String? lastMessage;
    for (final SshAuthMethod method in methods) {
      final SshAuthResult result = await _authenticateWithMethod(
        transport: transport,
        username: context.config.username,
        method: method,
      );
      if (result.isSuccess) {
        return result;
      }

      if (result.allowedMethods.isNotEmpty) {
        allowedMethods = result.allowedMethods;
      }
      if (result.message != null) {
        lastMessage = result.message;
      }
    }

    return SshAuthResult.failure(
      message: lastMessage ?? 'SSH authentication failed.',
      allowedMethods: allowedMethods,
    );
  }

  Future<void> _requestUserauthService(SshPacketTransport transport) async {
    await transport.writePacket(
      SshServiceRequestMessage(serviceName: userauthServiceName)
          .encodePayload(),
    );

    final SshBinaryPacket packet = await transport.readPacket();
    switch (packet.messageId) {
      case 6:
        final SshServiceAcceptMessage accept =
            SshServiceAcceptMessage.decodePayload(packet.payload);
        if (accept.serviceName != userauthServiceName) {
          throw SshAuthException(
            'SSH peer accepted unexpected service "${accept.serviceName}".',
          );
        }
        return;
      case 53:
        await _consumeBanner(packet);
        await _requestUserauthService(transport);
        return;
      default:
        throw SshAuthException(
          'Unexpected SSH packet during userauth service negotiation: '
          '${packet.messageId}.',
        );
    }
  }

  Future<SshAuthResult> _authenticateWithMethod({
    required SshPacketTransport transport,
    required String username,
    required SshAuthMethod method,
  }) async {
    if (method is SshNoneAuthMethod) {
      await transport.writePacket(
        SshUserAuthRequestMessage.none(
          username: username,
          serviceName: serviceName,
        ).encodePayload(),
      );
      return _readAuthResult(transport: transport, method: method);
    }

    if (method is SshPasswordAuthMethod) {
      await transport.writePacket(
        SshUserAuthRequestMessage.password(
          username: username,
          serviceName: serviceName,
          password: method.password,
          nextPassword: method.changePassword,
        ).encodePayload(),
      );
      return _readAuthResult(transport: transport, method: method);
    }

    if (method is SshKeyboardInteractiveAuthMethod) {
      await transport.writePacket(
        SshUserAuthRequestMessage.keyboardInteractive(
          username: username,
          serviceName: serviceName,
        ).encodePayload(),
      );
      return _readAuthResult(
        transport: transport,
        method: method,
        keyboardInteractiveResponder: method.respond,
      );
    }

    if (method is SshPublicKeyAuthMethod) {
      return const SshAuthResult.failure(
        message:
            'Public key userauth is not implemented yet in the protocol authenticator.',
      );
    }

    return SshAuthResult.failure(
      message: 'Unsupported SSH auth method: ${method.name}.',
    );
  }

  Future<SshAuthResult> _readAuthResult({
    required SshPacketTransport transport,
    required SshAuthMethod method,
    SshKeyboardInteractiveResponder? keyboardInteractiveResponder,
  }) async {
    for (;;) {
      final SshBinaryPacket packet = await transport.readPacket();
      switch (packet.messageId) {
        case 52:
          SshUserAuthSuccessMessage.decodePayload(packet.payload);
          return const SshAuthResult.success(message: 'Authenticated.');
        case 51:
          final SshUserAuthFailureMessage failure =
              SshUserAuthFailureMessage.decodePayload(packet.payload);
          return SshAuthResult.failure(
            message: 'SSH ${method.name} authentication failed.',
            allowedMethods: failure.allowedMethods,
          );
        case 53:
          await _consumeBanner(packet);
          continue;
        case 60:
          final SshKeyboardInteractiveResponder? responder =
              keyboardInteractiveResponder;
          if (responder == null) {
            throw SshAuthException(
              'Received SSH keyboard-interactive prompt for ${method.name}.',
            );
          }

          final SshUserAuthInfoRequestMessage infoRequest =
              SshUserAuthInfoRequestMessage.decodePayload(packet.payload);
          final List<String> responses = await responder(infoRequest.prompts);
          await transport.writePacket(
            SshUserAuthInfoResponseMessage(
              responses: responses,
            ).encodePayload(),
          );
          continue;
        default:
          throw SshAuthException(
            'Unexpected SSH packet during ${method.name} authentication: '
            '${packet.messageId}.',
          );
      }
    }
  }

  Future<void> _consumeBanner(SshBinaryPacket packet) async {
    SshUserAuthBannerMessage.decodePayload(packet.payload);
  }

  SshPacketTransport _requirePacketTransport(SshTransport transport) {
    if (transport is SshPacketTransport) {
      return transport;
    }

    throw const SshAuthException(
      'SSH authenticator requires a packet-capable transport.',
    );
  }
}
