class SshException implements Exception {
  const SshException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() => 'SshException(message: $message, cause: $cause)';
}

class SshStateException extends SshException {
  const SshStateException(super.message, {super.cause});
}

class SshAuthException extends SshException {
  const SshAuthException(super.message, {super.cause});
}

class SshHostKeyException extends SshException {
  const SshHostKeyException(super.message, {super.cause});
}

class SshDisconnectException extends SshException {
  SshDisconnectException({
    required this.reasonCode,
    required this.description,
    this.languageTag = '',
    super.cause,
  }) : super(_buildMessage(reasonCode: reasonCode, description: description));

  final int reasonCode;
  final String description;
  final String languageTag;

  static String _buildMessage({
    required int reasonCode,
    required String description,
  }) {
    if (description.isEmpty) {
      return 'SSH peer disconnected (reason $reasonCode).';
    }

    return 'SSH peer disconnected (reason $reasonCode): $description';
  }
}
