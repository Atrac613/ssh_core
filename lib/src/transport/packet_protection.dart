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
  final SshPacketCodec _codec;
  int _sequenceNumber = 0;

  @override
  Uint8List encode(List<int> payload) {
    final Uint8List plainPacket = _codec.encode(payload);
    final Uint8List mac = _computeMac(
      macKey: _macKey,
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
        _macLength = sshMacLength(macAlgorithm),
        _codec = codec ??
            SshPacketCodec(
              blockSize: initialVector.length,
            );

  final _SshAesCtrCipher _cipher;
  final Uint8List _macKey;
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

Uint8List _computeMac({
  required List<int> macKey,
  required int sequenceNumber,
  required List<int> packetBytes,
}) {
  final ByteData sequenceData = ByteData(4)..setUint32(0, sequenceNumber);
  final Uint8List macInput = Uint8List.fromList(<int>[
    ...sequenceData.buffer.asUint8List(),
    ...packetBytes,
  ]);
  return Uint8List.fromList(Hmac(sha256, macKey).convert(macInput).bytes);
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
