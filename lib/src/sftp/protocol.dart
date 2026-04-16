import 'dart:typed_data';

import '../transport/message_codec.dart';

enum SftpPacketType {
  init(1),
  version(2),
  open(3),
  close(4),
  read(5),
  write(6),
  opendir(11),
  readdir(12),
  remove(13),
  mkdir(14),
  rmdir(15),
  status(101),
  handle(102),
  data(103),
  name(104);

  const SftpPacketType(this.value);

  final int value;

  static SftpPacketType fromValue(int value) {
    return values.firstWhere(
      (SftpPacketType type) => type.value == value,
      orElse: () => throw FormatException('Unknown SFTP packet type: $value.'),
    );
  }
}

enum SftpStatusCode {
  ok(0),
  eof(1),
  noSuchFile(2),
  permissionDenied(3),
  failure(4),
  badMessage(5),
  noConnection(6),
  connectionLost(7),
  opUnsupported(8);

  const SftpStatusCode(this.value);

  final int value;

  static SftpStatusCode fromValue(int value) {
    return values.firstWhere(
      (SftpStatusCode code) => code.value == value,
      orElse: () => throw FormatException('Unknown SFTP status code: $value.'),
    );
  }
}

class SftpPacket {
  SftpPacket({
    required this.type,
    this.requestId,
    List<int> payload = const <int>[],
  }) : payload = Uint8List.fromList(payload);

  final SftpPacketType type;
  final int? requestId;
  final Uint8List payload;
}

class SftpPacketCodec {
  const SftpPacketCodec();

  Uint8List encode(SftpPacket packet) {
    final SshPayloadWriter bodyWriter = SshPayloadWriter()
      ..writeByte(packet.type.value);
    if (_packetCarriesRequestId(packet.type)) {
      final int requestId = packet.requestId ??
          (throw ArgumentError(
            'SFTP packet type ${packet.type.name} requires a request ID.',
          ));
      bodyWriter.writeUint32(requestId);
    } else if (packet.requestId != null) {
      throw ArgumentError(
        'SFTP packet type ${packet.type.name} must not include a request ID.',
      );
    }
    bodyWriter.writeBytes(packet.payload);

    final Uint8List body = bodyWriter.toBytes();
    final SshPayloadWriter frameWriter = SshPayloadWriter()
      ..writeUint32(body.length)
      ..writeBytes(body);
    return frameWriter.toBytes();
  }

  SftpPacket decode(List<int> frameBytes) {
    final SshPayloadReader frameReader = SshPayloadReader(frameBytes);
    final int frameLength = frameReader.readUint32();
    final Uint8List body = frameReader.readBytes(frameLength);
    frameReader.expectDone();

    final SshPayloadReader bodyReader = SshPayloadReader(body);
    final SftpPacketType type = SftpPacketType.fromValue(bodyReader.readByte());
    final int? requestId =
        _packetCarriesRequestId(type) ? bodyReader.readUint32() : null;
    final SftpPacket packet = SftpPacket(
      type: type,
      requestId: requestId,
      payload: bodyReader.readBytes(bodyReader.remainingByteCount),
    );
    bodyReader.expectDone();
    return packet;
  }

  bool _packetCarriesRequestId(SftpPacketType type) {
    return switch (type) {
      SftpPacketType.init || SftpPacketType.version => false,
      _ => true,
    };
  }
}

class SftpInitMessage {
  const SftpInitMessage({this.version = 3});

  factory SftpInitMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpInitMessage message =
        SftpInitMessage(version: reader.readUint32());
    reader.expectDone();
    return message;
  }

  final int version;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeUint32(version);
    return writer.toBytes();
  }

  SftpPacket toPacket() {
    return SftpPacket(
      type: SftpPacketType.init,
      payload: encodePayload(),
    );
  }
}

class SftpVersionMessage {
  SftpVersionMessage({
    this.version = 3,
    Map<String, String> extensions = const <String, String>{},
  }) : extensions = Map<String, String>.unmodifiable(extensions);

  factory SftpVersionMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int version = reader.readUint32();
    final Map<String, String> extensions = <String, String>{};
    while (!reader.isDone) {
      extensions[reader.readString()] = reader.readString();
    }

    return SftpVersionMessage(version: version, extensions: extensions);
  }

  final int version;
  final Map<String, String> extensions;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeUint32(version);
    for (final MapEntry<String, String> extension in extensions.entries) {
      writer
        ..writeString(extension.key)
        ..writeString(extension.value);
    }
    return writer.toBytes();
  }

  SftpPacket toPacket() {
    return SftpPacket(
      type: SftpPacketType.version,
      payload: encodePayload(),
    );
  }
}

class SftpFileAttributes {
  SftpFileAttributes({
    this.size,
    this.userId,
    this.groupId,
    this.permissions,
    this.accessTime,
    this.modifiedTime,
    Map<String, List<int>> extensions = const <String, List<int>>{},
  }) : extensions = Map<String, Uint8List>.unmodifiable(
          extensions.map(
            (String key, List<int> value) =>
                MapEntry<String, Uint8List>(key, Uint8List.fromList(value)),
          ),
        );

  const SftpFileAttributes.empty()
      : size = null,
        userId = null,
        groupId = null,
        permissions = null,
        accessTime = null,
        modifiedTime = null,
        extensions = const <String, Uint8List>{};

  factory SftpFileAttributes.decode(SshPayloadReader reader) {
    final int flags = reader.readUint32();
    final int? size =
        (flags & _sftpAttrSizeFlag) == 0 ? null : reader.readUint64();
    int? userId;
    int? groupId;
    if ((flags & _sftpAttrUidGidFlag) != 0) {
      userId = reader.readUint32();
      groupId = reader.readUint32();
    }

    final int? permissions =
        (flags & _sftpAttrPermissionsFlag) == 0 ? null : reader.readUint32();
    int? accessTime;
    int? modifiedTime;
    if ((flags & _sftpAttrAcmodTimeFlag) != 0) {
      accessTime = reader.readUint32();
      modifiedTime = reader.readUint32();
    }

    final Map<String, Uint8List> extensions = <String, Uint8List>{};
    if ((flags & _sftpAttrExtendedFlag) != 0) {
      final int extensionCount = reader.readUint32();
      for (int index = 0; index < extensionCount; index += 1) {
        extensions[reader.readString()] = reader.readStringBytes();
      }
    }

    return SftpFileAttributes(
      size: size,
      userId: userId,
      groupId: groupId,
      permissions: permissions,
      accessTime: accessTime,
      modifiedTime: modifiedTime,
      extensions: extensions,
    );
  }

  final int? size;
  final int? userId;
  final int? groupId;
  final int? permissions;
  final int? accessTime;
  final int? modifiedTime;
  final Map<String, Uint8List> extensions;

  bool get isEmpty =>
      size == null &&
      userId == null &&
      groupId == null &&
      permissions == null &&
      accessTime == null &&
      modifiedTime == null &&
      extensions.isEmpty;

  Uint8List encode() {
    int flags = 0;
    if (size != null) {
      flags |= _sftpAttrSizeFlag;
    }
    if (userId != null || groupId != null) {
      if (userId == null || groupId == null) {
        throw StateError(
          'SFTP file attributes require both userId and groupId together.',
        );
      }
      flags |= _sftpAttrUidGidFlag;
    }
    if (permissions != null) {
      flags |= _sftpAttrPermissionsFlag;
    }
    if (accessTime != null || modifiedTime != null) {
      if (accessTime == null || modifiedTime == null) {
        throw StateError(
          'SFTP file attributes require both accessTime and modifiedTime together.',
        );
      }
      flags |= _sftpAttrAcmodTimeFlag;
    }
    if (extensions.isNotEmpty) {
      flags |= _sftpAttrExtendedFlag;
    }

    final SshPayloadWriter writer = SshPayloadWriter()..writeUint32(flags);
    if (size != null) {
      writer.writeUint64(size!);
    }
    if ((flags & _sftpAttrUidGidFlag) != 0) {
      writer
        ..writeUint32(userId!)
        ..writeUint32(groupId!);
    }
    if (permissions != null) {
      writer.writeUint32(permissions!);
    }
    if ((flags & _sftpAttrAcmodTimeFlag) != 0) {
      writer
        ..writeUint32(accessTime!)
        ..writeUint32(modifiedTime!);
    }
    if (extensions.isNotEmpty) {
      writer.writeUint32(extensions.length);
      for (final MapEntry<String, Uint8List> extension in extensions.entries) {
        writer
          ..writeString(extension.key)
          ..writeStringBytes(extension.value);
      }
    }
    return writer.toBytes();
  }
}

class SftpStatusMessage {
  const SftpStatusMessage({
    required this.code,
    required this.message,
    this.languageTag = '',
  });

  factory SftpStatusMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpStatusMessage message = SftpStatusMessage(
      code: SftpStatusCode.fromValue(reader.readUint32()),
      message: reader.readString(),
      languageTag: reader.readString(),
    );
    reader.expectDone();
    return message;
  }

  final SftpStatusCode code;
  final String message;
  final String languageTag;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeUint32(code.value)
      ..writeString(message)
      ..writeString(languageTag);
    return writer.toBytes();
  }
}

class SftpHandleMessage {
  SftpHandleMessage({required List<int> handle})
      : handle = Uint8List.fromList(handle);

  factory SftpHandleMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpHandleMessage message = SftpHandleMessage(
      handle: reader.readStringBytes(),
    );
    reader.expectDone();
    return message;
  }

  final Uint8List handle;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeStringBytes(handle);
    return writer.toBytes();
  }
}

class SftpDataMessage {
  SftpDataMessage({required List<int> data}) : data = Uint8List.fromList(data);

  factory SftpDataMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpDataMessage message = SftpDataMessage(
      data: reader.readStringBytes(),
    );
    reader.expectDone();
    return message;
  }

  final Uint8List data;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeStringBytes(data);
    return writer.toBytes();
  }
}

class SftpNameEntry {
  const SftpNameEntry({
    required this.filename,
    required this.longname,
    this.attributes = const SftpFileAttributes.empty(),
  });

  final String filename;
  final String longname;
  final SftpFileAttributes attributes;
}

class SftpNameMessage {
  SftpNameMessage({List<SftpNameEntry> entries = const <SftpNameEntry>[]})
      : entries = List<SftpNameEntry>.unmodifiable(entries);

  factory SftpNameMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int entryCount = reader.readUint32();
    final List<SftpNameEntry> entries = <SftpNameEntry>[];
    for (int index = 0; index < entryCount; index += 1) {
      entries.add(
        SftpNameEntry(
          filename: reader.readString(),
          longname: reader.readString(),
          attributes: SftpFileAttributes.decode(reader),
        ),
      );
    }
    reader.expectDone();
    return SftpNameMessage(entries: entries);
  }

  final List<SftpNameEntry> entries;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeUint32(entries.length);
    for (final SftpNameEntry entry in entries) {
      writer
        ..writeString(entry.filename)
        ..writeString(entry.longname)
        ..writeBytes(entry.attributes.encode());
    }
    return writer.toBytes();
  }
}

class SftpOpenRequest {
  const SftpOpenRequest({
    required this.filename,
    required this.pflags,
    this.attributes = const SftpFileAttributes.empty(),
  });

  factory SftpOpenRequest.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpOpenRequest request = SftpOpenRequest(
      filename: reader.readString(),
      pflags: reader.readUint32(),
      attributes: SftpFileAttributes.decode(reader),
    );
    reader.expectDone();
    return request;
  }

  final String filename;
  final int pflags;
  final SftpFileAttributes attributes;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(filename)
      ..writeUint32(pflags)
      ..writeBytes(attributes.encode());
    return writer.toBytes();
  }
}

class SftpCloseRequest {
  SftpCloseRequest({required List<int> handle})
      : handle = Uint8List.fromList(handle);

  factory SftpCloseRequest.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpCloseRequest request = SftpCloseRequest(
      handle: reader.readStringBytes(),
    );
    reader.expectDone();
    return request;
  }

  final Uint8List handle;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeStringBytes(handle);
    return writer.toBytes();
  }
}

class SftpReadRequest {
  SftpReadRequest({
    required List<int> handle,
    required this.offset,
    required this.length,
  }) : handle = Uint8List.fromList(handle);

  factory SftpReadRequest.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpReadRequest request = SftpReadRequest(
      handle: reader.readStringBytes(),
      offset: reader.readUint64(),
      length: reader.readUint32(),
    );
    reader.expectDone();
    return request;
  }

  final Uint8List handle;
  final int offset;
  final int length;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeStringBytes(handle)
      ..writeUint64(offset)
      ..writeUint32(length);
    return writer.toBytes();
  }
}

class SftpWriteRequest {
  SftpWriteRequest({
    required List<int> handle,
    required this.offset,
    required List<int> data,
  })  : handle = Uint8List.fromList(handle),
        data = Uint8List.fromList(data);

  factory SftpWriteRequest.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpWriteRequest request = SftpWriteRequest(
      handle: reader.readStringBytes(),
      offset: reader.readUint64(),
      data: reader.readStringBytes(),
    );
    reader.expectDone();
    return request;
  }

  final Uint8List handle;
  final int offset;
  final Uint8List data;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeStringBytes(handle)
      ..writeUint64(offset)
      ..writeStringBytes(data);
    return writer.toBytes();
  }
}

class SftpPathRequest {
  const SftpPathRequest({
    required this.path,
    required this.type,
    this.attributes = const SftpFileAttributes.empty(),
  });

  factory SftpPathRequest.decodePayload(
      List<int> payload, SftpPacketType type) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpPathRequest request = SftpPathRequest(
      path: reader.readString(),
      type: type,
      attributes: type == SftpPacketType.mkdir
          ? SftpFileAttributes.decode(reader)
          : const SftpFileAttributes.empty(),
    );
    reader.expectDone();
    return request;
  }

  final String path;
  final SftpPacketType type;
  final SftpFileAttributes attributes;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeString(path);
    if (type == SftpPacketType.mkdir) {
      writer.writeBytes(attributes.encode());
    }
    return writer.toBytes();
  }
}

class SftpHandleRequest {
  SftpHandleRequest({required this.type, required List<int> handle})
      : handle = Uint8List.fromList(handle);

  factory SftpHandleRequest.decodePayload(
    List<int> payload,
    SftpPacketType type,
  ) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SftpHandleRequest request = SftpHandleRequest(
      type: type,
      handle: reader.readStringBytes(),
    );
    reader.expectDone();
    return request;
  }

  final SftpPacketType type;
  final Uint8List handle;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeStringBytes(handle);
    return writer.toBytes();
  }
}

const int _sftpAttrSizeFlag = 0x00000001;
const int _sftpAttrUidGidFlag = 0x00000002;
const int _sftpAttrPermissionsFlag = 0x00000004;
const int _sftpAttrAcmodTimeFlag = 0x00000008;
const int _sftpAttrExtendedFlag = 0x80000000;
