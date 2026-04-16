import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc hide Signature;
import 'package:ssh_core/ssh_core.dart';
import 'package:test/test.dart';

void main() {
  test('verifies rsa-sha2-256 exchange hash signatures', () {
    final Uint8List exchangeHash = Uint8List.fromList(
      List<int>.generate(32, (int index) => index + 1),
    );
    final _GeneratedRsaKeyPair keyPair = _generateRsaKeyPair();
    final SshHostKey hostKey = SshHostKey.decode(
      (SshPayloadWriter()
            ..writeString(sshRsaHostKeyType)
            ..writeMpInt(keyPair.publicKey.exponent!)
            ..writeMpInt(keyPair.publicKey.modulus!))
          .toBytes(),
    );
    final pc.RSASigner signer = pc.RSASigner(
      pc.SHA256Digest(),
      '0609608648016503040201',
    )..init(
        true,
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(keyPair.privateKey),
      );

    final SshSignature signature = SshSignature(
      algorithm: sshRsaSha256HostKeyAlgorithm,
      blob: signer.generateSignature(exchangeHash).bytes,
    );

    expect(
      const SshHostKeySignatureVerifier().verifyExchangeHash(
        hostKey: hostKey,
        signature: signature,
        exchangeHash: exchangeHash,
        negotiatedHostKeyAlgorithm: sshRsaSha256HostKeyAlgorithm,
      ),
      isTrue,
    );
  });

  test('verifies ecdsa-sha2-nistp256 exchange hash signatures', () {
    final Uint8List exchangeHash = Uint8List.fromList(
      List<int>.generate(32, (int index) => 255 - index),
    );
    final _GeneratedEcdsaKeyPair keyPair = _generateEcdsaKeyPair();
    final SshHostKey hostKey = SshHostKey.decode(
      (SshPayloadWriter()
            ..writeString(sshEcdsaSha2Nistp256HostKeyAlgorithm)
            ..writeString('nistp256')
            ..writeStringBytes(keyPair.publicKey.Q!.getEncoded(false)))
          .toBytes(),
    );
    final pc.ECDSASigner signer =
        pc.Signer('SHA-256/DET-ECDSA') as pc.ECDSASigner
          ..init(
            true,
            pc.PrivateKeyParameter<pc.ECPrivateKey>(keyPair.privateKey),
          );
    final pc.ECSignature signatureValue =
        signer.generateSignature(exchangeHash) as pc.ECSignature;
    final SshSignature signature = SshSignature(
      algorithm: sshEcdsaSha2Nistp256HostKeyAlgorithm,
      blob: (SshPayloadWriter()
            ..writeMpInt(signatureValue.r)
            ..writeMpInt(signatureValue.s))
          .toBytes(),
    );

    expect(
      const SshHostKeySignatureVerifier().verifyExchangeHash(
        hostKey: hostKey,
        signature: signature,
        exchangeHash: exchangeHash,
        negotiatedHostKeyAlgorithm: sshEcdsaSha2Nistp256HostKeyAlgorithm,
      ),
      isTrue,
    );
  });

  test('protects packets with aes192-ctr and hmac-sha2-512', () {
    final SshAesCtrHmacPacketWriterState writer =
        SshAesCtrHmacPacketWriterState(
      encryptionKey: List<int>.generate(24, (int index) => index + 1),
      initialVector: List<int>.generate(16, (int index) => 16 - index),
      macKey: List<int>.generate(64, (int index) => 255 - index),
      macAlgorithm: sshHmacSha512Mac,
    );
    final SshAesCtrHmacPacketReaderState reader =
        SshAesCtrHmacPacketReaderState(
      encryptionKey: List<int>.generate(24, (int index) => index + 1),
      initialVector: List<int>.generate(16, (int index) => 16 - index),
      macKey: List<int>.generate(64, (int index) => 255 - index),
      macAlgorithm: sshHmacSha512Mac,
    );

    final Uint8List encoded = writer.encode(
      <int>[SshMessageId.ignore.value, 1, 2, 3, 4],
    );
    final SshBinaryPacket? packet = reader.tryRead(encoded);

    expect(packet, isNotNull);
    expect(packet!.messageId, SshMessageId.ignore.value);
  });

  test('triggers rekey policy when thresholds are met', () {
    const SshRekeyPolicy policy = SshRekeyPolicy(
      maxPackets: 4,
      maxBytes: 128,
      maxDuration: Duration(minutes: 5),
    );

    expect(
      policy.shouldRekey(
        sentPackets: 4,
        receivedPackets: 0,
        sentBytes: 32,
        receivedBytes: 0,
        elapsed: const Duration(minutes: 1),
      ),
      isTrue,
    );
    expect(
      policy.shouldRekey(
        sentPackets: 1,
        receivedPackets: 1,
        sentBytes: 16,
        receivedBytes: 16,
        elapsed: const Duration(minutes: 5),
      ),
      isTrue,
    );
    expect(
      policy.shouldRekey(
        sentPackets: 1,
        receivedPackets: 1,
        sentBytes: 16,
        receivedBytes: 16,
        elapsed: const Duration(minutes: 1),
      ),
      isFalse,
    );
  });
}

class _GeneratedRsaKeyPair {
  const _GeneratedRsaKeyPair({
    required this.publicKey,
    required this.privateKey,
  });

  final pc.RSAPublicKey publicKey;
  final pc.RSAPrivateKey privateKey;
}

class _GeneratedEcdsaKeyPair {
  const _GeneratedEcdsaKeyPair({
    required this.publicKey,
    required this.privateKey,
  });

  final pc.ECPublicKey publicKey;
  final pc.ECPrivateKey privateKey;
}

_GeneratedRsaKeyPair _generateRsaKeyPair() {
  final pc.FortunaRandom random = _seededRandom(
    List<int>.generate(32, (int index) => index + 1),
  );
  final pc.RSAKeyGenerator generator = pc.RSAKeyGenerator()
    ..init(
      pc.ParametersWithRandom<pc.RSAKeyGeneratorParameters>(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 64),
        random,
      ),
    );
  final pc.AsymmetricKeyPair<pc.PublicKey, pc.PrivateKey> pair =
      generator.generateKeyPair();
  return _GeneratedRsaKeyPair(
    publicKey: pair.publicKey as pc.RSAPublicKey,
    privateKey: pair.privateKey as pc.RSAPrivateKey,
  );
}

_GeneratedEcdsaKeyPair _generateEcdsaKeyPair() {
  final pc.ECDomainParameters curve = pc.ECCurve_secp256r1();
  final pc.FortunaRandom random = _seededRandom(
    List<int>.generate(32, (int index) => 32 - index),
  );
  final pc.ECKeyGenerator generator = pc.ECKeyGenerator()
    ..init(
      pc.ParametersWithRandom<pc.ECKeyGeneratorParameters>(
        pc.ECKeyGeneratorParameters(curve),
        random,
      ),
    );
  final pc.AsymmetricKeyPair<pc.PublicKey, pc.PrivateKey> pair =
      generator.generateKeyPair();
  return _GeneratedEcdsaKeyPair(
    publicKey: pair.publicKey as pc.ECPublicKey,
    privateKey: pair.privateKey as pc.ECPrivateKey,
  );
}

pc.FortunaRandom _seededRandom(List<int> seedBytes) {
  final pc.FortunaRandom random = pc.FortunaRandom();
  random.seed(pc.KeyParameter(Uint8List.fromList(seedBytes)));
  return random;
}
