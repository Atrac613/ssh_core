import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

import 'crypto.dart';
import 'transport.dart';

abstract class SshPacketWriterState {
  Uint8List encode(List<int> payload);
}

abstract class SshPacketReaderState {
  int? expectedFrameLength(List<int> buffer);

  SshBinaryPacket? tryRead(List<int> buffer);
}

SshPacketWriterState sshCreatePacketWriterState({
  required String encryptionAlgorithm,
  required List<int> encryptionKey,
  required List<int> initialVector,
  required String macAlgorithm,
  required List<int> macKey,
}) {
  final SshCipherAlgorithm cipher =
      SshTransportAlgorithms.cipherAlgorithm(encryptionAlgorithm);
  switch (cipher.protectionMode) {
    case SshPacketProtectionMode.plain:
      return SshPlainPacketWriterState(
        codec: SshPacketCodec(blockSize: cipher.blockSize),
      );
    case SshPacketProtectionMode.encryptThenMac:
      return SshAesCtrHmacPacketWriterState(
        encryptionKey: encryptionKey,
        initialVector: initialVector,
        macKey: macKey,
        macAlgorithm: macAlgorithm,
        codec: SshPacketCodec(blockSize: cipher.blockSize),
      );
    case SshPacketProtectionMode.aead:
      return SshChaCha20Poly1305PacketWriterState(
        encryptionKey: encryptionKey,
        codec: SshPacketCodec(blockSize: cipher.blockSize),
      );
  }
}

SshPacketReaderState sshCreatePacketReaderState({
  required String encryptionAlgorithm,
  required List<int> encryptionKey,
  required List<int> initialVector,
  required String macAlgorithm,
  required List<int> macKey,
}) {
  final SshCipherAlgorithm cipher =
      SshTransportAlgorithms.cipherAlgorithm(encryptionAlgorithm);
  switch (cipher.protectionMode) {
    case SshPacketProtectionMode.plain:
      return SshPlainPacketReaderState(
        codec: SshPacketCodec(blockSize: cipher.blockSize),
      );
    case SshPacketProtectionMode.encryptThenMac:
      return SshAesCtrHmacPacketReaderState(
        encryptionKey: encryptionKey,
        initialVector: initialVector,
        macKey: macKey,
        macAlgorithm: macAlgorithm,
        codec: SshPacketCodec(blockSize: cipher.blockSize),
      );
    case SshPacketProtectionMode.aead:
      return SshChaCha20Poly1305PacketReaderState(
        encryptionKey: encryptionKey,
        codec: SshPacketCodec(blockSize: cipher.blockSize),
      );
  }
}

class SshPlainPacketWriterState implements SshPacketWriterState {
  SshPlainPacketWriterState({SshPacketCodec codec = const SshPacketCodec()})
      : _codec = codec;

  final SshPacketCodec _codec;

  @override
  Uint8List encode(List<int> payload) => _codec.encode(payload);
}

class SshPlainPacketReaderState implements SshPacketReaderState {
  SshPlainPacketReaderState({SshPacketCodec codec = const SshPacketCodec()})
      : _codec = codec;

  final SshPacketCodec _codec;

  @override
  int? expectedFrameLength(List<int> buffer) {
    if (buffer.length < 4) {
      return null;
    }

    final int packetLength = _readUint32(buffer, 0);
    return packetLength + 4;
  }

  @override
  SshBinaryPacket? tryRead(List<int> buffer) {
    final int? frameLength = expectedFrameLength(buffer);
    if (frameLength == null || buffer.length < frameLength) {
      return null;
    }
    return _codec.decode(buffer.sublist(0, frameLength));
  }
}

class SshAesCtrHmacPacketWriterState implements SshPacketWriterState {
  SshAesCtrHmacPacketWriterState({
    required List<int> encryptionKey,
    required List<int> initialVector,
    required List<int> macKey,
    this.macAlgorithm = sshHmacSha256Mac,
    SshPacketCodec? codec,
  })  : _cipher = _SshAesCtrCipher(
          key: encryptionKey,
          initialCounter: initialVector,
        ),
        _macKey = Uint8List.fromList(macKey),
        _codec = codec ??
            SshPacketCodec(
              blockSize: initialVector.length,
            );

  final _SshAesCtrCipher _cipher;
  final Uint8List _macKey;
  final String macAlgorithm;
  final SshPacketCodec _codec;
  int _sequenceNumber = 0;

  @override
  Uint8List encode(List<int> payload) {
    final Uint8List plainPacket = _codec.encode(payload);
    final Uint8List mac = _computeMac(
      macKey: _macKey,
      macAlgorithm: macAlgorithm,
      sequenceNumber: _sequenceNumber,
      packetBytes: plainPacket,
    );
    final Uint8List encryptedPacket = _cipher.transform(plainPacket);
    _sequenceNumber = (_sequenceNumber + 1) & 0xFFFFFFFF;
    return Uint8List.fromList(<int>[...encryptedPacket, ...mac]);
  }
}

class SshAesCtrHmacPacketReaderState implements SshPacketReaderState {
  SshAesCtrHmacPacketReaderState({
    required List<int> encryptionKey,
    required List<int> initialVector,
    required List<int> macKey,
    required String macAlgorithm,
    SshPacketCodec? codec,
  })  : _cipher = _SshAesCtrCipher(
          key: encryptionKey,
          initialCounter: initialVector,
        ),
        _macKey = Uint8List.fromList(macKey),
        _macAlgorithm = macAlgorithm,
        _macLength = sshMacLength(macAlgorithm),
        _codec = codec ??
            SshPacketCodec(
              blockSize: initialVector.length,
            );

  final _SshAesCtrCipher _cipher;
  final Uint8List _macKey;
  final String _macAlgorithm;
  final int _macLength;
  final SshPacketCodec _codec;
  int _sequenceNumber = 0;

  @override
  int? expectedFrameLength(List<int> buffer) {
    if (buffer.length < _cipher.blockSize) {
      return null;
    }

    final _SshAesCtrCipher probeCipher = _cipher.copy();
    final Uint8List firstBlock = probeCipher.transform(
      Uint8List.fromList(buffer.sublist(0, _cipher.blockSize)),
    );
    final int packetLength = _readUint32(firstBlock, 0);
    return packetLength + 4 + _macLength;
  }

  @override
  SshBinaryPacket? tryRead(List<int> buffer) {
    final int? requiredLength = expectedFrameLength(buffer);
    if (requiredLength == null || buffer.length < requiredLength) {
      return null;
    }

    final int frameLength = requiredLength - _macLength;
    final Uint8List encryptedPacket = Uint8List.fromList(
      buffer.sublist(0, frameLength),
    );
    final Uint8List receivedMac = Uint8List.fromList(
      buffer.sublist(frameLength, requiredLength),
    );
    final Uint8List plainPacket = _cipher.transform(encryptedPacket);
    final Uint8List expectedMac = _computeMac(
      macKey: _macKey,
      macAlgorithm: _macAlgorithm,
      sequenceNumber: _sequenceNumber,
      packetBytes: plainPacket,
    );
    if (!_constantTimeEquals(receivedMac, expectedMac)) {
      throw const SshTransportCryptoException(
        'SSH packet MAC verification failed.',
      );
    }

    final SshBinaryPacket packet = _codec.decode(plainPacket);
    _sequenceNumber = (_sequenceNumber + 1) & 0xFFFFFFFF;
    return packet;
  }
}

class SshChaCha20Poly1305PacketWriterState implements SshPacketWriterState {
  SshChaCha20Poly1305PacketWriterState({
    required List<int> encryptionKey,
    SshPacketCodec? codec,
  })  : _key = Uint8List.fromList(encryptionKey),
        _codec = codec ?? const SshPacketCodec() {
    if (_key.length != 64) {
      throw ArgumentError.value(
        _key.length,
        'encryptionKey.length',
        'SSH chacha20-poly1305 requires a 64-byte key.',
      );
    }
  }

  final Uint8List _key;
  final SshPacketCodec _codec;
  int _sequenceNumber = 0;

  @override
  Uint8List encode(List<int> payload) {
    final Uint8List plainPacket = _codec.encode(payload);
    final Uint8List encryptedLength = _lengthCipher.transform(
      plainPacket.sublist(0, 4),
      sequenceNumber: _sequenceNumber,
      initialBlockCounter: 0,
    );
    final Uint8List encryptedBody = _payloadCipher.transform(
      plainPacket.sublist(4),
      sequenceNumber: _sequenceNumber,
      initialBlockCounter: 1,
    );
    final Uint8List ciphertext = Uint8List.fromList(<int>[
      ...encryptedLength,
      ...encryptedBody,
    ]);
    final Uint8List tag = _poly1305Mac(
      key: _payloadCipher.keystream(
        sequenceNumber: _sequenceNumber,
        initialBlockCounter: 0,
        length: 32,
      ),
      message: ciphertext,
    );
    _sequenceNumber = (_sequenceNumber + 1) & 0xFFFFFFFF;
    return Uint8List.fromList(<int>[...ciphertext, ...tag]);
  }

  _SshOpenSshChaCha20Cipher get _payloadCipher => _SshOpenSshChaCha20Cipher(
        key: _key.sublist(0, 32),
      );

  _SshOpenSshChaCha20Cipher get _lengthCipher => _SshOpenSshChaCha20Cipher(
        key: _key.sublist(32),
      );
}

class SshChaCha20Poly1305PacketReaderState implements SshPacketReaderState {
  SshChaCha20Poly1305PacketReaderState({
    required List<int> encryptionKey,
    SshPacketCodec? codec,
  })  : _key = Uint8List.fromList(encryptionKey),
        _codec = codec ?? const SshPacketCodec() {
    if (_key.length != 64) {
      throw ArgumentError.value(
        _key.length,
        'encryptionKey.length',
        'SSH chacha20-poly1305 requires a 64-byte key.',
      );
    }
  }

  final Uint8List _key;
  final SshPacketCodec _codec;
  int _sequenceNumber = 0;

  @override
  int? expectedFrameLength(List<int> buffer) {
    if (buffer.length < 4) {
      return null;
    }

    final Uint8List decryptedLength = _lengthCipher.transform(
      buffer.sublist(0, 4),
      sequenceNumber: _sequenceNumber,
      initialBlockCounter: 0,
    );
    final int packetLength = _readUint32(decryptedLength, 0);
    return packetLength + 4 + _SshOpenSshChaCha20Cipher.tagLength;
  }

  @override
  SshBinaryPacket? tryRead(List<int> buffer) {
    final int? requiredLength = expectedFrameLength(buffer);
    if (requiredLength == null || buffer.length < requiredLength) {
      return null;
    }

    final int frameLength =
        requiredLength - _SshOpenSshChaCha20Cipher.tagLength;
    final Uint8List ciphertext = Uint8List.fromList(
      buffer.sublist(0, frameLength),
    );
    final Uint8List receivedTag = Uint8List.fromList(
      buffer.sublist(frameLength, requiredLength),
    );
    final Uint8List expectedTag = _poly1305Mac(
      key: _payloadCipher.keystream(
        sequenceNumber: _sequenceNumber,
        initialBlockCounter: 0,
        length: 32,
      ),
      message: ciphertext,
    );
    if (!_constantTimeEquals(receivedTag, expectedTag)) {
      throw const SshTransportCryptoException(
        'SSH packet AEAD verification failed.',
      );
    }

    final Uint8List plainLength = _lengthCipher.transform(
      ciphertext.sublist(0, 4),
      sequenceNumber: _sequenceNumber,
      initialBlockCounter: 0,
    );
    final Uint8List plainBody = _payloadCipher.transform(
      ciphertext.sublist(4),
      sequenceNumber: _sequenceNumber,
      initialBlockCounter: 1,
    );
    final SshBinaryPacket packet = _codec.decode(
      Uint8List.fromList(<int>[...plainLength, ...plainBody]),
    );
    _sequenceNumber = (_sequenceNumber + 1) & 0xFFFFFFFF;
    return packet;
  }

  _SshOpenSshChaCha20Cipher get _payloadCipher => _SshOpenSshChaCha20Cipher(
        key: _key.sublist(0, 32),
      );

  _SshOpenSshChaCha20Cipher get _lengthCipher => _SshOpenSshChaCha20Cipher(
        key: _key.sublist(32),
      );
}

class _SshAesCtrCipher {
  _SshAesCtrCipher({
    required List<int> key,
    required List<int> initialCounter,
  })  : _key = Uint8List.fromList(key),
        _counter = Uint8List.fromList(initialCounter),
        _keystreamBlock = Uint8List(initialCounter.length),
        blockSize = initialCounter.length {
    _engine.init(true, KeyParameter(_key));
    _keystreamOffset = blockSize;
  }

  _SshAesCtrCipher._copy({
    required Uint8List key,
    required Uint8List counter,
    required Uint8List keystreamBlock,
    required int keystreamOffset,
  })  : _key = Uint8List.fromList(key),
        _counter = Uint8List.fromList(counter),
        _keystreamBlock = Uint8List.fromList(keystreamBlock),
        _keystreamOffset = keystreamOffset,
        blockSize = counter.length {
    _engine.init(true, KeyParameter(_key));
  }

  final Uint8List _key;
  final Uint8List _counter;
  final Uint8List _keystreamBlock;
  final int blockSize;
  final AESEngine _engine = AESEngine();
  int _keystreamOffset = 0;

  _SshAesCtrCipher copy() {
    return _SshAesCtrCipher._copy(
      key: _key,
      counter: _counter,
      keystreamBlock: _keystreamBlock,
      keystreamOffset: _keystreamOffset,
    );
  }

  Uint8List transform(List<int> input) {
    final Uint8List output = Uint8List(input.length);
    for (int index = 0; index < input.length; index += 1) {
      if (_keystreamOffset >= blockSize) {
        _engine.processBlock(_counter, 0, _keystreamBlock, 0);
        _incrementCounter(_counter);
        _keystreamOffset = 0;
      }

      output[index] = input[index] ^ _keystreamBlock[_keystreamOffset];
      _keystreamOffset += 1;
    }
    return output;
  }
}

class _SshOpenSshChaCha20Cipher {
  _SshOpenSshChaCha20Cipher({required List<int> key})
      : _key = Uint8List.fromList(key) {
    if (_key.length != 32) {
      throw ArgumentError.value(
        _key.length,
        'key.length',
        'SSH chacha20-poly1305 requires 32-byte subkeys.',
      );
    }
  }

  static const int tagLength = 16;

  final Uint8List _key;

  Uint8List transform(
    List<int> input, {
    required int sequenceNumber,
    required int initialBlockCounter,
  }) {
    final ChaCha7539Engine engine = ChaCha7539Engine();
    engine.init(
      true,
      ParametersWithIV<KeyParameter>(
        KeyParameter(_key),
        _nonceForSequence(sequenceNumber),
      ),
    );

    if (initialBlockCounter > 0) {
      final int skipLength = 64 * initialBlockCounter;
      final Uint8List skipInput = Uint8List(skipLength);
      final Uint8List skipOutput = Uint8List(skipLength);
      engine.processBytes(skipInput, 0, skipLength, skipOutput, 0);
    }

    final Uint8List output = Uint8List(input.length);
    final Uint8List source = Uint8List.fromList(input);
    engine.processBytes(source, 0, source.length, output, 0);
    return output;
  }

  Uint8List keystream({
    required int sequenceNumber,
    required int initialBlockCounter,
    required int length,
  }) {
    return transform(
      Uint8List(length),
      sequenceNumber: sequenceNumber,
      initialBlockCounter: initialBlockCounter,
    );
  }

  Uint8List _nonceForSequence(int sequenceNumber) {
    final Uint8List nonce = Uint8List(12);
    final ByteData nonceData = ByteData.sublistView(nonce);
    nonceData.setUint32(8, sequenceNumber, Endian.big);
    return nonce;
  }
}

Uint8List _computeMac({
  required List<int> macKey,
  required String macAlgorithm,
  required int sequenceNumber,
  required List<int> packetBytes,
}) {
  final ByteData sequenceData = ByteData(4)..setUint32(0, sequenceNumber);
  final Uint8List macInput = Uint8List.fromList(<int>[
    ...sequenceData.buffer.asUint8List(),
    ...packetBytes,
  ]);
  switch (macAlgorithm) {
    case sshHmacSha256Mac:
      return Uint8List.fromList(Hmac(sha256, macKey).convert(macInput).bytes);
    case sshHmacSha512Mac:
      return Uint8List.fromList(Hmac(sha512, macKey).convert(macInput).bytes);
  }

  throw SshTransportCryptoException(
    'Unsupported SSH MAC algorithm: $macAlgorithm.',
  );
}

Uint8List _poly1305Mac({
  required List<int> key,
  required List<int> message,
}) {
  final Poly1305 poly1305 = Poly1305()
    ..init(KeyParameter(Uint8List.fromList(key)));
  final Uint8List source = Uint8List.fromList(message);
  poly1305.update(source, 0, source.length);
  final Uint8List tag = Uint8List(poly1305.macSize);
  poly1305.doFinal(tag, 0);
  return tag;
}

void _incrementCounter(Uint8List counter) {
  for (int index = counter.length - 1; index >= 0; index -= 1) {
    counter[index] = (counter[index] + 1) & 0xFF;
    if (counter[index] != 0) {
      return;
    }
  }
}

bool _constantTimeEquals(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }

  int diff = 0;
  for (int index = 0; index < left.length; index += 1) {
    diff |= left[index] ^ right[index];
  }
  return diff == 0;
}

int _readUint32(List<int> bytes, int offset) {
  return (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
}
