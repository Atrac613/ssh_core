import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/tweetnacl.dart';

import 'host_key.dart';
import 'key_exchange.dart';
import 'message_codec.dart';
import 'signature.dart';

const String sshCurve25519Sha256 = 'curve25519-sha256';
const String sshCurve25519Sha256LibSsh = 'curve25519-sha256@libssh.org';
const String sshEd25519HostKeyAlgorithm = 'ssh-ed25519';
const String sshAes128CtrCipher = 'aes128-ctr';
const String sshAes256CtrCipher = 'aes256-ctr';
const String sshHmacSha256Mac = 'hmac-sha2-256';
const String sshNoCompression = 'none';

class SshTransportCryptoException implements Exception {
  const SshTransportCryptoException(this.message);

  final String message;

  @override
  String toString() => 'SshTransportCryptoException($message)';
}

class SshCurve25519KeyPair {
  SshCurve25519KeyPair._({
    required List<int> privateKey,
    required List<int> publicKey,
  })  : privateKey = Uint8List.fromList(privateKey),
        publicKey = Uint8List.fromList(publicKey);

  factory SshCurve25519KeyPair.generate([Random? random]) {
    final Random secureRandom = random ?? Random.secure();
    final Uint8List privateKey = Uint8List(32);
    for (int index = 0; index < privateKey.length; index += 1) {
      privateKey[index] = secureRandom.nextInt(256);
    }

    final Uint8List publicKey = Uint8List(32);
    TweetNaCl.crypto_scalarmult_base(publicKey, privateKey);
    return SshCurve25519KeyPair._(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  final Uint8List privateKey;
  final Uint8List publicKey;

  BigInt computeSharedSecret(List<int> remotePublicKey) {
    if (remotePublicKey.length != 32) {
      throw ArgumentError.value(
        remotePublicKey.length,
        'remotePublicKey.length',
        'Curve25519 public keys must be 32 bytes long.',
      );
    }

    final Uint8List sharedSecretBytes = Uint8List(32);
    final Uint8List peerKey = Uint8List.fromList(remotePublicKey);
    TweetNaCl.crypto_scalarmult(sharedSecretBytes, privateKey, peerKey);
    return _decodeUnsignedBigInt(sharedSecretBytes);
  }
}

class SshExchangeHashComputer {
  const SshExchangeHashComputer();

  Uint8List sha256FromInput(SshKexEcdhExchangeHashInput input) {
    return Uint8List.fromList(sha256.convert(input.encode()).bytes);
  }
}

class SshKeyDerivationContext {
  const SshKeyDerivationContext({
    required this.sharedSecret,
    required this.exchangeHash,
    required this.sessionIdentifier,
  });

  final BigInt sharedSecret;
  final List<int> exchangeHash;
  final List<int> sessionIdentifier;
}

class SshDerivedKeys {
  const SshDerivedKeys({
    required this.initialIvClientToServer,
    required this.initialIvServerToClient,
    required this.encryptionKeyClientToServer,
    required this.encryptionKeyServerToClient,
    required this.integrityKeyClientToServer,
    required this.integrityKeyServerToClient,
  });

  final Uint8List initialIvClientToServer;
  final Uint8List initialIvServerToClient;
  final Uint8List encryptionKeyClientToServer;
  final Uint8List encryptionKeyServerToClient;
  final Uint8List integrityKeyClientToServer;
  final Uint8List integrityKeyServerToClient;
}

class SshKeyDerivation {
  const SshKeyDerivation();

  SshDerivedKeys deriveSha256({
    required SshKeyDerivationContext context,
    required int ivLength,
    required int encryptionKeyLength,
    required int integrityKeyLength,
  }) {
    return SshDerivedKeys(
      initialIvClientToServer: _derive(
        context: context,
        discriminator: 0x41,
        length: ivLength,
      ),
      initialIvServerToClient: _derive(
        context: context,
        discriminator: 0x42,
        length: ivLength,
      ),
      encryptionKeyClientToServer: _derive(
        context: context,
        discriminator: 0x43,
        length: encryptionKeyLength,
      ),
      encryptionKeyServerToClient: _derive(
        context: context,
        discriminator: 0x44,
        length: encryptionKeyLength,
      ),
      integrityKeyClientToServer: _derive(
        context: context,
        discriminator: 0x45,
        length: integrityKeyLength,
      ),
      integrityKeyServerToClient: _derive(
        context: context,
        discriminator: 0x46,
        length: integrityKeyLength,
      ),
    );
  }

  Uint8List _derive({
    required SshKeyDerivationContext context,
    required int discriminator,
    required int length,
  }) {
    final BytesBuilder material = BytesBuilder(copy: false);
    material.add(
      _hash(
        context: context,
        suffixBuilder: (SshPayloadWriter writer) {
          writer
            ..writeByte(discriminator)
            ..writeBytes(context.sessionIdentifier);
        },
      ),
    );

    while (material.length < length) {
      final Uint8List previous = material.toBytes();
      material.add(
        _hash(
          context: context,
          suffixBuilder: (SshPayloadWriter writer) {
            writer.writeBytes(previous);
          },
        ),
      );
    }

    return Uint8List.fromList(material.takeBytes().sublist(0, length));
  }

  Uint8List _hash({
    required SshKeyDerivationContext context,
    required void Function(SshPayloadWriter writer) suffixBuilder,
  }) {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeMpInt(context.sharedSecret)
      ..writeBytes(context.exchangeHash);
    suffixBuilder(writer);
    return Uint8List.fromList(sha256.convert(writer.toBytes()).bytes);
  }
}

class SshHostKeySignatureVerifier {
  const SshHostKeySignatureVerifier();

  bool verifyExchangeHash({
    required SshHostKey hostKey,
    required SshSignature signature,
    required List<int> exchangeHash,
  }) {
    switch (hostKey.algorithm) {
      case sshEd25519HostKeyAlgorithm:
        return _verifyEd25519(
          hostKey: hostKey,
          signature: signature,
          exchangeHash: exchangeHash,
        );
    }

    throw SshTransportCryptoException(
      'Unsupported SSH host key algorithm: ${hostKey.algorithm}.',
    );
  }

  bool _verifyEd25519({
    required SshHostKey hostKey,
    required SshSignature signature,
    required List<int> exchangeHash,
  }) {
    if (signature.algorithm != sshEd25519HostKeyAlgorithm) {
      throw SshTransportCryptoException(
        'Expected an ssh-ed25519 signature, received ${signature.algorithm}.',
      );
    }

    final SshPayloadReader reader = SshPayloadReader(hostKey.encodedBytes);
    final String algorithm = reader.readString();
    if (algorithm != sshEd25519HostKeyAlgorithm) {
      throw SshTransportCryptoException(
        'Expected an ssh-ed25519 host key, received $algorithm.',
      );
    }

    final Uint8List publicKey = reader.readStringBytes();
    reader.expectDone();

    return VerifyKey(publicKey).verify(
      signature: Signature(Uint8List.fromList(signature.blob)),
      message: Uint8List.fromList(exchangeHash),
    );
  }
}

int sshCipherKeyLength(String algorithm) {
  switch (algorithm) {
    case sshAes128CtrCipher:
      return 16;
    case sshAes256CtrCipher:
      return 32;
  }

  throw SshTransportCryptoException(
    'Unsupported SSH encryption algorithm: $algorithm.',
  );
}

int sshCipherBlockSize(String algorithm) {
  switch (algorithm) {
    case sshAes128CtrCipher:
    case sshAes256CtrCipher:
      return 16;
  }

  throw SshTransportCryptoException(
    'Unsupported SSH encryption algorithm: $algorithm.',
  );
}

int sshMacKeyLength(String algorithm) {
  switch (algorithm) {
    case sshHmacSha256Mac:
      return 32;
  }

  throw SshTransportCryptoException(
    'Unsupported SSH MAC algorithm: $algorithm.',
  );
}

int sshMacLength(String algorithm) {
  switch (algorithm) {
    case sshHmacSha256Mac:
      return 32;
  }

  throw SshTransportCryptoException(
    'Unsupported SSH MAC algorithm: $algorithm.',
  );
}

BigInt _decodeUnsignedBigInt(List<int> bytes) {
  BigInt value = BigInt.zero;
  for (final int byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}
