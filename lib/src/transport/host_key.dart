import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'message_codec.dart';

class SshHostKey {
  SshHostKey({
    required this.algorithm,
    required List<int> encodedBytes,
  }) : encodedBytes = Uint8List.fromList(encodedBytes);

  factory SshHostKey.decode(List<int> encodedBytes) {
    final SshPayloadReader reader = SshPayloadReader(encodedBytes);
    final String algorithm = reader.readString();
    final Uint8List publicKeyData = reader.readBytes(reader.remainingByteCount);
    reader.expectDone();

    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(algorithm)
      ..writeBytes(publicKeyData);
    return SshHostKey(
      algorithm: algorithm,
      encodedBytes: writer.toBytes(),
    );
  }

  final String algorithm;
  final Uint8List encodedBytes;

  String get base64Encoded => base64.encode(encodedBytes);

  bool matches(SshHostKey other) {
    if (algorithm != other.algorithm) {
      return false;
    }

    if (encodedBytes.length != other.encodedBytes.length) {
      return false;
    }

    for (int index = 0; index < encodedBytes.length; index += 1) {
      if (encodedBytes[index] != other.encodedBytes[index]) {
        return false;
      }
    }

    return true;
  }
}

class SshHostKeyVerificationContext {
  const SshHostKeyVerificationContext({
    required this.host,
    required this.port,
    required this.localIdentification,
    required this.remoteIdentification,
    required this.hostKey,
  });

  final String host;
  final int port;
  final String localIdentification;
  final String remoteIdentification;
  final SshHostKey hostKey;
}

class SshHostKeyVerificationResult {
  const SshHostKeyVerificationResult._({
    required this.isSuccess,
    this.message,
  });

  const SshHostKeyVerificationResult.success({String? message})
      : this._(isSuccess: true, message: message);

  const SshHostKeyVerificationResult.failure({String? message})
      : this._(isSuccess: false, message: message);

  final bool isSuccess;
  final String? message;
}

abstract class SshHostKeyVerifier {
  Future<SshHostKeyVerificationResult> verify(
    SshHostKeyVerificationContext context,
  );
}

class SshAllowAnyHostKeyVerifier implements SshHostKeyVerifier {
  const SshAllowAnyHostKeyVerifier();

  @override
  Future<SshHostKeyVerificationResult> verify(
    SshHostKeyVerificationContext context,
  ) async {
    return const SshHostKeyVerificationResult.success();
  }
}

class SshTrustedHostKey {
  const SshTrustedHostKey({
    required this.host,
    this.port = 22,
    required this.hostKey,
  });

  final String host;
  final int port;
  final SshHostKey hostKey;

  bool matchesEndpoint(String candidateHost, int candidatePort) {
    return host == candidateHost && port == candidatePort;
  }
}

class SshStaticHostKeyVerifier implements SshHostKeyVerifier {
  SshStaticHostKeyVerifier({
    required List<SshTrustedHostKey> trustedKeys,
    this.allowUntrustedHosts = false,
  }) : trustedKeys = List.unmodifiable(trustedKeys);

  final List<SshTrustedHostKey> trustedKeys;
  final bool allowUntrustedHosts;

  @override
  Future<SshHostKeyVerificationResult> verify(
    SshHostKeyVerificationContext context,
  ) async {
    final List<SshTrustedHostKey> matchingTrustedKeys =
        trustedKeys.where((SshTrustedHostKey entry) {
      return entry.matchesEndpoint(context.host, context.port);
    }).toList(growable: false);

    if (matchingTrustedKeys.isEmpty) {
      if (allowUntrustedHosts) {
        return const SshHostKeyVerificationResult.success();
      }

      return SshHostKeyVerificationResult.failure(
        message:
            'No trusted SSH host key is registered for ${context.host}:${context.port}.',
      );
    }

    for (final SshTrustedHostKey trustedKey in matchingTrustedKeys) {
      if (trustedKey.hostKey.matches(context.hostKey)) {
        return const SshHostKeyVerificationResult.success();
      }
    }

    return SshHostKeyVerificationResult.failure(
      message: 'SSH host key mismatch for ${context.host}:${context.port}.',
    );
  }
}
