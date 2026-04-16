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
