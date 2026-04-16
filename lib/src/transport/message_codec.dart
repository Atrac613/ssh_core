import 'dart:convert';
import 'dart:typed_data';

enum SshMessageId {
  disconnect(1),
  ignore(2),
  serviceRequest(5),
  serviceAccept(6),
  kexInit(20),
  newKeys(21),
  userauthRequest(50),
  userauthFailure(51),
  userauthSuccess(52),
  channelOpen(90),
  channelData(94),
  channelClose(97);

  const SshMessageId(this.value);

  final int value;
}

class SshPayloadWriter {
  final BytesBuilder _builder = BytesBuilder(copy: false);

  void writeByte(int value) {
    RangeError.checkValueInInterval(value, 0, 255, 'value');
    _builder.add(<int>[value]);
  }

  void writeBool(bool value) {
    writeByte(value ? 1 : 0);
  }

  void writeUint32(int value) {
    RangeError.checkValueInInterval(value, 0, 0xFFFFFFFF, 'value');
    final ByteData data = ByteData(4)..setUint32(0, value);
    _builder.add(data.buffer.asUint8List());
  }

  void writeBytes(List<int> value) {
    _builder.add(value);
  }

  void writeString(String value) {
    writeStringBytes(utf8.encode(value));
  }

  void writeStringBytes(List<int> value) {
    writeUint32(value.length);
    writeBytes(value);
  }

  void writeNameList(List<String> names) {
    for (final String name in names) {
      if (name.contains(',')) {
        throw ArgumentError.value(
          name,
          'names',
          'SSH name-list entries must not contain commas.',
        );
      }
    }

    writeString(names.join(','));
  }

  Uint8List toBytes() => _builder.takeBytes();
}

class SshPayloadReader {
  SshPayloadReader(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;
  int _offset = 0;

  int get remainingByteCount => _bytes.length - _offset;

  bool get isDone => remainingByteCount == 0;

  int readByte() {
    _requireAvailable(1);
    return _bytes[_offset++];
  }

  bool readBool() => readByte() != 0;

  int readUint32() {
    _requireAvailable(4);
    final int value = (_bytes[_offset] << 24) |
        (_bytes[_offset + 1] << 16) |
        (_bytes[_offset + 2] << 8) |
        _bytes[_offset + 3];
    _offset += 4;
    return value;
  }

  Uint8List readBytes(int length) {
    RangeError.checkNotNegative(length, 'length');
    _requireAvailable(length);
    final Uint8List value = Uint8List.fromList(
      _bytes.sublist(_offset, _offset + length),
    );
    _offset += length;
    return value;
  }

  Uint8List readStringBytes() {
    final int length = readUint32();
    return readBytes(length);
  }

  String readString() {
    return utf8.decode(readStringBytes());
  }

  List<String> readNameList() {
    final String value = readString();
    if (value.isEmpty) {
      return const <String>[];
    }
    return value.split(',');
  }

  void expectDone() {
    if (!isDone) {
      throw FormatException(
        'SSH payload had $remainingByteCount trailing bytes.',
      );
    }
  }

  void _requireAvailable(int length) {
    if (remainingByteCount < length) {
      throw FormatException(
        'SSH payload ended early. Needed $length bytes, '
        'but only $remainingByteCount remain.',
      );
    }
  }
}

class SshKexInitMessage {
  SshKexInitMessage({
    required List<int> cookie,
    List<String> kexAlgorithms = const <String>[],
    List<String> serverHostKeyAlgorithms = const <String>[],
    List<String> encryptionAlgorithmsClientToServer = const <String>[],
    List<String> encryptionAlgorithmsServerToClient = const <String>[],
    List<String> macAlgorithmsClientToServer = const <String>[],
    List<String> macAlgorithmsServerToClient = const <String>[],
    List<String> compressionAlgorithmsClientToServer = const <String>[],
    List<String> compressionAlgorithmsServerToClient = const <String>[],
    List<String> languagesClientToServer = const <String>[],
    List<String> languagesServerToClient = const <String>[],
    this.firstKexPacketFollows = false,
    this.reserved = 0,
  })  : cookie = Uint8List.fromList(cookie),
        kexAlgorithms = List.unmodifiable(kexAlgorithms),
        serverHostKeyAlgorithms = List.unmodifiable(serverHostKeyAlgorithms),
        encryptionAlgorithmsClientToServer = List.unmodifiable(
          encryptionAlgorithmsClientToServer,
        ),
        encryptionAlgorithmsServerToClient = List.unmodifiable(
          encryptionAlgorithmsServerToClient,
        ),
        macAlgorithmsClientToServer = List.unmodifiable(
          macAlgorithmsClientToServer,
        ),
        macAlgorithmsServerToClient = List.unmodifiable(
          macAlgorithmsServerToClient,
        ),
        compressionAlgorithmsClientToServer = List.unmodifiable(
          compressionAlgorithmsClientToServer,
        ),
        compressionAlgorithmsServerToClient = List.unmodifiable(
          compressionAlgorithmsServerToClient,
        ),
        languagesClientToServer = List.unmodifiable(languagesClientToServer),
        languagesServerToClient = List.unmodifiable(languagesServerToClient) {
    if (this.cookie.length != 16) {
      throw ArgumentError.value(
        this.cookie.length,
        'cookie',
        'SSH KEXINIT cookie must be exactly 16 bytes long.',
      );
    }
  }

  factory SshKexInitMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.kexInit.value) {
      throw FormatException(
        'Expected SSH_MSG_KEXINIT (${SshMessageId.kexInit.value}), '
        'received $messageId.',
      );
    }

    final SshKexInitMessage message = SshKexInitMessage(
      cookie: reader.readBytes(16),
      kexAlgorithms: reader.readNameList(),
      serverHostKeyAlgorithms: reader.readNameList(),
      encryptionAlgorithmsClientToServer: reader.readNameList(),
      encryptionAlgorithmsServerToClient: reader.readNameList(),
      macAlgorithmsClientToServer: reader.readNameList(),
      macAlgorithmsServerToClient: reader.readNameList(),
      compressionAlgorithmsClientToServer: reader.readNameList(),
      compressionAlgorithmsServerToClient: reader.readNameList(),
      languagesClientToServer: reader.readNameList(),
      languagesServerToClient: reader.readNameList(),
      firstKexPacketFollows: reader.readBool(),
      reserved: reader.readUint32(),
    );
    reader.expectDone();
    return message;
  }

  final Uint8List cookie;
  final List<String> kexAlgorithms;
  final List<String> serverHostKeyAlgorithms;
  final List<String> encryptionAlgorithmsClientToServer;
  final List<String> encryptionAlgorithmsServerToClient;
  final List<String> macAlgorithmsClientToServer;
  final List<String> macAlgorithmsServerToClient;
  final List<String> compressionAlgorithmsClientToServer;
  final List<String> compressionAlgorithmsServerToClient;
  final List<String> languagesClientToServer;
  final List<String> languagesServerToClient;
  final bool firstKexPacketFollows;
  final int reserved;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.kexInit.value)
      ..writeBytes(cookie)
      ..writeNameList(kexAlgorithms)
      ..writeNameList(serverHostKeyAlgorithms)
      ..writeNameList(encryptionAlgorithmsClientToServer)
      ..writeNameList(encryptionAlgorithmsServerToClient)
      ..writeNameList(macAlgorithmsClientToServer)
      ..writeNameList(macAlgorithmsServerToClient)
      ..writeNameList(compressionAlgorithmsClientToServer)
      ..writeNameList(compressionAlgorithmsServerToClient)
      ..writeNameList(languagesClientToServer)
      ..writeNameList(languagesServerToClient)
      ..writeBool(firstKexPacketFollows)
      ..writeUint32(reserved);
    return writer.toBytes();
  }
}
