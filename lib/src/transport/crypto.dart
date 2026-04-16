import 'dart:math';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/tweetnacl.dart';
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/export.dart' hide Signature;

import 'host_key.dart';
import 'key_exchange.dart';
import 'message_codec.dart';
import 'signature.dart';

const String sshCurve25519Sha256 = 'curve25519-sha256';
const String sshCurve25519Sha256LibSsh = 'curve25519-sha256@libssh.org';
const String sshEd25519HostKeyAlgorithm = 'ssh-ed25519';
const String sshRsaHostKeyType = 'ssh-rsa';
const String sshRsaSha256HostKeyAlgorithm = 'rsa-sha2-256';
const String sshRsaSha512HostKeyAlgorithm = 'rsa-sha2-512';
const String sshEcdsaSha2Nistp256HostKeyAlgorithm = 'ecdsa-sha2-nistp256';
const String sshAes128CtrCipher = 'aes128-ctr';
const String sshAes192CtrCipher = 'aes192-ctr';
const String sshAes256CtrCipher = 'aes256-ctr';
const String sshHmacSha256Mac = 'hmac-sha2-256';
const String sshHmacSha512Mac = 'hmac-sha2-512';
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
    return Uint8List.fromList(crypto.sha256.convert(input.encode()).bytes);
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
    return Uint8List.fromList(crypto.sha256.convert(writer.toBytes()).bytes);
  }
}

class SshHostKeySignatureVerifier {
  const SshHostKeySignatureVerifier();

  bool verifyExchangeHash({
    required SshHostKey hostKey,
    required SshSignature signature,
    required List<int> exchangeHash,
    String? negotiatedHostKeyAlgorithm,
  }) {
    final String expectedAlgorithm =
        negotiatedHostKeyAlgorithm ?? hostKey.algorithm;

    switch (expectedAlgorithm) {
      case sshEd25519HostKeyAlgorithm:
        return _verifyEd25519(
          hostKey: hostKey,
          signature: signature,
          exchangeHash: exchangeHash,
        );
      case sshRsaHostKeyType:
      case sshRsaSha256HostKeyAlgorithm:
      case sshRsaSha512HostKeyAlgorithm:
        return _verifyRsa(
          hostKey: hostKey,
          signature: signature,
          exchangeHash: exchangeHash,
          algorithm: expectedAlgorithm,
        );
      case sshEcdsaSha2Nistp256HostKeyAlgorithm:
        return _verifyEcdsa(
          hostKey: hostKey,
          signature: signature,
          exchangeHash: exchangeHash,
          algorithm: expectedAlgorithm,
        );
    }

    throw SshTransportCryptoException(
      'Unsupported SSH host key algorithm: $expectedAlgorithm.',
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

  bool _verifyRsa({
    required SshHostKey hostKey,
    required SshSignature signature,
    required List<int> exchangeHash,
    required String algorithm,
  }) {
    if (hostKey.algorithm != sshRsaHostKeyType) {
      throw SshTransportCryptoException(
        'Expected an ssh-rsa host key, received ${hostKey.algorithm}.',
      );
    }
    if (signature.algorithm != algorithm) {
      throw SshTransportCryptoException(
        'Expected an $algorithm signature, received ${signature.algorithm}.',
      );
    }

    final SshPayloadReader reader = SshPayloadReader(hostKey.encodedBytes);
    final String keyType = reader.readString();
    if (keyType != sshRsaHostKeyType) {
      throw SshTransportCryptoException(
        'Expected an ssh-rsa host key, received $keyType.',
      );
    }
    final BigInt exponent = reader.readMpInt();
    final BigInt modulus = reader.readMpInt();
    reader.expectDone();

    final RSASigner verifier = _rsaSignerForAlgorithm(algorithm);
    verifier.init(
      false,
      PublicKeyParameter<asymmetric.RSAPublicKey>(
        asymmetric.RSAPublicKey(modulus, exponent),
      ),
    );
    return verifier.verifySignature(
      Uint8List.fromList(exchangeHash),
      asymmetric.RSASignature(Uint8List.fromList(signature.blob)),
    );
  }

  bool _verifyEcdsa({
    required SshHostKey hostKey,
    required SshSignature signature,
    required List<int> exchangeHash,
    required String algorithm,
  }) {
    if (hostKey.algorithm != algorithm) {
      throw SshTransportCryptoException(
        'Expected an $algorithm host key, received ${hostKey.algorithm}.',
      );
    }
    if (signature.algorithm != algorithm) {
      throw SshTransportCryptoException(
        'Expected an $algorithm signature, received ${signature.algorithm}.',
      );
    }

    final SshPayloadReader hostKeyReader =
        SshPayloadReader(hostKey.encodedBytes);
    final String keyType = hostKeyReader.readString();
    if (keyType != algorithm) {
      throw SshTransportCryptoException(
        'Expected an $algorithm host key, received $keyType.',
      );
    }
    final String curveName = hostKeyReader.readString();
    final Uint8List publicPointBytes = hostKeyReader.readStringBytes();
    hostKeyReader.expectDone();

    final ECDomainParameters curve = _ecdsaCurveForName(curveName);
    final ECPoint? publicPoint = curve.curve.decodePoint(publicPointBytes);
    if (publicPoint == null) {
      throw const SshTransportCryptoException(
        'SSH ECDSA host key contained an invalid public point.',
      );
    }

    final SshPayloadReader signatureReader = SshPayloadReader(signature.blob);
    final BigInt r = signatureReader.readMpInt();
    final BigInt s = signatureReader.readMpInt();
    signatureReader.expectDone();

    final ECDSASigner verifier = ECDSASigner(_ecdsaDigestForCurve(curveName));
    verifier.init(false, PublicKeyParameter(ECPublicKey(publicPoint, curve)));
    return verifier.verifySignature(
      Uint8List.fromList(exchangeHash),
      ECSignature(r, s),
    );
  }
}

int sshCipherKeyLength(String algorithm) {
  switch (algorithm) {
    case sshAes128CtrCipher:
      return 16;
    case sshAes192CtrCipher:
      return 24;
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
    case sshAes192CtrCipher:
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
    case sshHmacSha512Mac:
      return 64;
  }

  throw SshTransportCryptoException(
    'Unsupported SSH MAC algorithm: $algorithm.',
  );
}

int sshMacLength(String algorithm) {
  switch (algorithm) {
    case sshHmacSha256Mac:
      return 32;
    case sshHmacSha512Mac:
      return 64;
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

RSASigner _rsaSignerForAlgorithm(String algorithm) {
  switch (algorithm) {
    case sshRsaHostKeyType:
      return RSASigner(SHA1Digest(), '06052b0e03021a');
    case sshRsaSha256HostKeyAlgorithm:
      return RSASigner(SHA256Digest(), '0609608648016503040201');
    case sshRsaSha512HostKeyAlgorithm:
      return RSASigner(SHA512Digest(), '0609608648016503040203');
  }

  throw SshTransportCryptoException(
    'Unsupported SSH RSA signature algorithm: $algorithm.',
  );
}

ECDomainParameters _ecdsaCurveForName(String curveName) {
  switch (curveName) {
    case 'nistp256':
      return ECCurve_secp256r1();
  }

  throw SshTransportCryptoException(
    'Unsupported SSH ECDSA curve: $curveName.',
  );
}

Digest _ecdsaDigestForCurve(String curveName) {
  switch (curveName) {
    case 'nistp256':
      return SHA256Digest();
  }

  throw SshTransportCryptoException(
    'Unsupported SSH ECDSA curve: $curveName.',
  );
}
