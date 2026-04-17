typedef SshDigestName = String;

const String sshCurve25519Sha256 = 'curve25519-sha256';
const String sshCurve25519Sha256LibSsh = 'curve25519-sha256@libssh.org';
const String sshEd25519HostKeyAlgorithm = 'ssh-ed25519';
const String sshRsaHostKeyType = 'ssh-rsa';
const String sshRsaSha256HostKeyAlgorithm = 'rsa-sha2-256';
const String sshRsaSha512HostKeyAlgorithm = 'rsa-sha2-512';
const String sshEcdsaSha2Nistp256HostKeyAlgorithm = 'ecdsa-sha2-nistp256';
const String sshEcdsaSha2Nistp384HostKeyAlgorithm = 'ecdsa-sha2-nistp384';
const String sshEcdsaSha2Nistp521HostKeyAlgorithm = 'ecdsa-sha2-nistp521';
const String sshChaCha20Poly1305OpenSshCipher = 'chacha20-poly1305@openssh.com';
const String sshAes128CtrCipher = 'aes128-ctr';
const String sshAes192CtrCipher = 'aes192-ctr';
const String sshAes256CtrCipher = 'aes256-ctr';
const String sshHmacSha256Mac = 'hmac-sha2-256';
const String sshHmacSha512Mac = 'hmac-sha2-512';
const String sshNoCompression = 'none';
const String sshZlibCompression = 'zlib';
const String sshZlibOpenSshCompression = 'zlib@openssh.com';

enum SshPacketProtectionMode { plain, encryptThenMac, aead }

class SshKeyExchangeAlgorithm {
  const SshKeyExchangeAlgorithm(this.name);

  final String name;
}

class SshHostKeyAlgorithm {
  const SshHostKeyAlgorithm({
    required this.name,
    required this.hostKeyType,
    this.curveName,
    this.digestName,
  });

  final String name;
  final String hostKeyType;
  final String? curveName;
  final SshDigestName? digestName;

  bool get isEd25519 => name == sshEd25519HostKeyAlgorithm;

  bool get isRsa =>
      name == sshRsaHostKeyType ||
      name == sshRsaSha256HostKeyAlgorithm ||
      name == sshRsaSha512HostKeyAlgorithm;

  bool get isEcdsa => curveName != null;
}

class SshCipherAlgorithm {
  const SshCipherAlgorithm({
    required this.name,
    required this.keyLength,
    required this.ivLength,
    required this.blockSize,
    this.protectionMode = SshPacketProtectionMode.encryptThenMac,
    this.macEmbedded = false,
    this.tagLength = 0,
  });

  final String name;
  final int keyLength;
  final int ivLength;
  final int blockSize;
  final SshPacketProtectionMode protectionMode;
  final bool macEmbedded;
  final int tagLength;
}

class SshMacAlgorithm {
  const SshMacAlgorithm({
    required this.name,
    required this.keyLength,
    required this.macLength,
  });

  final String name;
  final int keyLength;
  final int macLength;
}

class SshCompressionAlgorithm {
  const SshCompressionAlgorithm({
    required this.name,
    required this.normalizedName,
  });

  final String name;
  final String normalizedName;

  bool get isDelayedUntilAuthenticated => name == sshZlibOpenSshCompression;
}

final class SshTransportAlgorithms {
  const SshTransportAlgorithms._();

  static const List<String> defaultKeyExchangeAlgorithms = <String>[
    sshCurve25519Sha256,
    sshCurve25519Sha256LibSsh,
  ];

  static const List<String> defaultServerHostKeyAlgorithms = <String>[
    sshEd25519HostKeyAlgorithm,
    sshEcdsaSha2Nistp521HostKeyAlgorithm,
    sshEcdsaSha2Nistp384HostKeyAlgorithm,
    sshEcdsaSha2Nistp256HostKeyAlgorithm,
    sshRsaSha512HostKeyAlgorithm,
    sshRsaSha256HostKeyAlgorithm,
  ];

  static const List<String> defaultEncryptionAlgorithms = <String>[
    sshAes128CtrCipher,
    sshAes192CtrCipher,
    sshAes256CtrCipher,
    sshChaCha20Poly1305OpenSshCipher,
  ];

  static const List<String> defaultMacAlgorithms = <String>[
    sshHmacSha256Mac,
    sshHmacSha512Mac,
  ];

  static const List<String> defaultCompressionAlgorithms = <String>[
    sshNoCompression,
  ];

  static const Map<String, SshKeyExchangeAlgorithm> _keyExchangeAlgorithms =
      <String, SshKeyExchangeAlgorithm>{
    sshCurve25519Sha256: SshKeyExchangeAlgorithm(sshCurve25519Sha256),
    sshCurve25519Sha256LibSsh: SshKeyExchangeAlgorithm(
      sshCurve25519Sha256LibSsh,
    ),
  };

  static const Map<String, SshHostKeyAlgorithm> _hostKeyAlgorithms =
      <String, SshHostKeyAlgorithm>{
    sshEd25519HostKeyAlgorithm: SshHostKeyAlgorithm(
      name: sshEd25519HostKeyAlgorithm,
      hostKeyType: sshEd25519HostKeyAlgorithm,
    ),
    sshRsaHostKeyType: SshHostKeyAlgorithm(
      name: sshRsaHostKeyType,
      hostKeyType: sshRsaHostKeyType,
      digestName: 'sha1',
    ),
    sshRsaSha256HostKeyAlgorithm: SshHostKeyAlgorithm(
      name: sshRsaSha256HostKeyAlgorithm,
      hostKeyType: sshRsaHostKeyType,
      digestName: 'sha256',
    ),
    sshRsaSha512HostKeyAlgorithm: SshHostKeyAlgorithm(
      name: sshRsaSha512HostKeyAlgorithm,
      hostKeyType: sshRsaHostKeyType,
      digestName: 'sha512',
    ),
    sshEcdsaSha2Nistp256HostKeyAlgorithm: SshHostKeyAlgorithm(
      name: sshEcdsaSha2Nistp256HostKeyAlgorithm,
      hostKeyType: sshEcdsaSha2Nistp256HostKeyAlgorithm,
      curveName: 'nistp256',
      digestName: 'sha256',
    ),
    sshEcdsaSha2Nistp384HostKeyAlgorithm: SshHostKeyAlgorithm(
      name: sshEcdsaSha2Nistp384HostKeyAlgorithm,
      hostKeyType: sshEcdsaSha2Nistp384HostKeyAlgorithm,
      curveName: 'nistp384',
      digestName: 'sha384',
    ),
    sshEcdsaSha2Nistp521HostKeyAlgorithm: SshHostKeyAlgorithm(
      name: sshEcdsaSha2Nistp521HostKeyAlgorithm,
      hostKeyType: sshEcdsaSha2Nistp521HostKeyAlgorithm,
      curveName: 'nistp521',
      digestName: 'sha512',
    ),
  };

  static const Map<String, SshCipherAlgorithm> _cipherAlgorithms =
      <String, SshCipherAlgorithm>{
    sshChaCha20Poly1305OpenSshCipher: SshCipherAlgorithm(
      name: sshChaCha20Poly1305OpenSshCipher,
      keyLength: 64,
      ivLength: 0,
      blockSize: 8,
      protectionMode: SshPacketProtectionMode.aead,
      macEmbedded: true,
      tagLength: 16,
    ),
    sshAes128CtrCipher: SshCipherAlgorithm(
      name: sshAes128CtrCipher,
      keyLength: 16,
      ivLength: 16,
      blockSize: 16,
    ),
    sshAes192CtrCipher: SshCipherAlgorithm(
      name: sshAes192CtrCipher,
      keyLength: 24,
      ivLength: 16,
      blockSize: 16,
    ),
    sshAes256CtrCipher: SshCipherAlgorithm(
      name: sshAes256CtrCipher,
      keyLength: 32,
      ivLength: 16,
      blockSize: 16,
    ),
  };

  static const Map<String, SshMacAlgorithm> _macAlgorithms =
      <String, SshMacAlgorithm>{
    sshHmacSha256Mac: SshMacAlgorithm(
      name: sshHmacSha256Mac,
      keyLength: 32,
      macLength: 32,
    ),
    sshHmacSha512Mac: SshMacAlgorithm(
      name: sshHmacSha512Mac,
      keyLength: 64,
      macLength: 64,
    ),
  };

  static const Map<String, SshCompressionAlgorithm> _compressionAlgorithms =
      <String, SshCompressionAlgorithm>{
    sshNoCompression: SshCompressionAlgorithm(
      name: sshNoCompression,
      normalizedName: sshNoCompression,
    ),
    sshZlibCompression: SshCompressionAlgorithm(
      name: sshZlibCompression,
      normalizedName: sshZlibCompression,
    ),
    sshZlibOpenSshCompression: SshCompressionAlgorithm(
      name: sshZlibOpenSshCompression,
      normalizedName: sshZlibCompression,
    ),
  };

  static SshKeyExchangeAlgorithm keyExchangeAlgorithm(String name) {
    final SshKeyExchangeAlgorithm? algorithm = _keyExchangeAlgorithms[name];
    if (algorithm == null) {
      throw ArgumentError.value(
        name,
        'name',
        'Unsupported SSH key exchange algorithm.',
      );
    }
    return algorithm;
  }

  static SshHostKeyAlgorithm hostKeyAlgorithm(String name) {
    final SshHostKeyAlgorithm? algorithm = _hostKeyAlgorithms[name];
    if (algorithm == null) {
      throw ArgumentError.value(
        name,
        'name',
        'Unsupported SSH host key algorithm.',
      );
    }
    return algorithm;
  }

  static SshCipherAlgorithm cipherAlgorithm(String name) {
    final SshCipherAlgorithm? algorithm = _cipherAlgorithms[name];
    if (algorithm == null) {
      throw ArgumentError.value(
        name,
        'name',
        'Unsupported SSH encryption algorithm.',
      );
    }
    return algorithm;
  }

  static SshMacAlgorithm macAlgorithm(String name) {
    final SshMacAlgorithm? algorithm = _macAlgorithms[name];
    if (algorithm == null) {
      throw ArgumentError.value(name, 'name', 'Unsupported SSH MAC algorithm.');
    }
    return algorithm;
  }

  static SshCompressionAlgorithm compressionAlgorithm(String name) {
    final SshCompressionAlgorithm? algorithm = _compressionAlgorithms[name];
    if (algorithm == null) {
      throw ArgumentError.value(
        name,
        'name',
        'Unsupported SSH compression algorithm.',
      );
    }
    return algorithm;
  }
}
