import '../core/config.dart';
import '../transport/transport.dart';

abstract class SshAuthMethod {
  const SshAuthMethod();

  String get name;
}

class SshNoneAuthMethod extends SshAuthMethod {
  const SshNoneAuthMethod();

  @override
  String get name => 'none';
}

class SshPasswordAuthMethod extends SshAuthMethod {
  const SshPasswordAuthMethod({required this.password, this.changePassword});

  final String password;
  final String? changePassword;

  @override
  String get name => 'password';
}

typedef SshSignCallback = Future<List<int>> Function(List<int> challenge);

class SshPublicKeyAuthMethod extends SshAuthMethod {
  const SshPublicKeyAuthMethod({
    required this.algorithm,
    required this.publicKey,
    required this.sign,
  });

  final String algorithm;
  final List<int> publicKey;
  final SshSignCallback sign;

  @override
  String get name => 'publickey';
}

class SshKeyboardInteractivePrompt {
  const SshKeyboardInteractivePrompt({required this.prompt, this.echo = false});

  final String prompt;
  final bool echo;
}

typedef SshKeyboardInteractiveResponder =
    Future<List<String>> Function(List<SshKeyboardInteractivePrompt> prompts);

class SshKeyboardInteractiveAuthMethod extends SshAuthMethod {
  const SshKeyboardInteractiveAuthMethod({required this.respond});

  final SshKeyboardInteractiveResponder respond;

  @override
  String get name => 'keyboard-interactive';
}

class SshAuthContext {
  const SshAuthContext({
    required this.config,
    required this.transport,
    required this.handshake,
  });

  final SshClientConfig config;
  final SshTransport transport;
  final SshHandshakeInfo handshake;
}

class SshAuthResult {
  const SshAuthResult.success({this.message})
    : isSuccess = true,
      allowedMethods = const <String>[];

  const SshAuthResult.failure({
    this.message,
    this.allowedMethods = const <String>[],
  }) : isSuccess = false;

  final bool isSuccess;
  final String? message;
  final List<String> allowedMethods;
}

abstract class SshAuthenticator {
  Future<SshAuthResult> authenticate({
    required SshAuthContext context,
    required List<SshAuthMethod> methods,
  });
}
