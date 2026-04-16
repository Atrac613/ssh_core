import 'dart:typed_data';

enum SshSocks5AuthMethod {
  noAuth(0x00),
  gssApi(0x01),
  usernamePassword(0x02),
  noAcceptableMethods(0xFF);

  const SshSocks5AuthMethod(this.code);

  final int code;

  static SshSocks5AuthMethod fromCode(int code) {
    return values.firstWhere(
      (SshSocks5AuthMethod value) => value.code == code,
      orElse: () => throw FormatException('Unknown SOCKS5 auth method: $code.'),
    );
  }
}

enum SshSocks5Command {
  connect(0x01),
  bind(0x02),
  udpAssociate(0x03);

  const SshSocks5Command(this.code);

  final int code;

  static SshSocks5Command fromCode(int code) {
    return values.firstWhere(
      (SshSocks5Command value) => value.code == code,
      orElse: () => throw FormatException('Unknown SOCKS5 command: $code.'),
    );
  }
}

enum SshSocks5AddressType {
  ipv4(0x01),
  domainName(0x03),
  ipv6(0x04);

  const SshSocks5AddressType(this.code);

  final int code;

  static SshSocks5AddressType fromCode(int code) {
    return values.firstWhere(
      (SshSocks5AddressType value) => value.code == code,
      orElse: () =>
          throw FormatException('Unknown SOCKS5 address type: $code.'),
    );
  }
}

enum SshSocks5ReplyCode {
  succeeded(0x00),
  generalFailure(0x01),
  connectionNotAllowed(0x02),
  networkUnreachable(0x03),
  hostUnreachable(0x04),
  connectionRefused(0x05),
  ttlExpired(0x06),
  commandNotSupported(0x07),
  addressTypeNotSupported(0x08);

  const SshSocks5ReplyCode(this.code);

  final int code;

  static SshSocks5ReplyCode fromCode(int code) {
    return values.firstWhere(
      (SshSocks5ReplyCode value) => value.code == code,
      orElse: () => throw FormatException('Unknown SOCKS5 reply code: $code.'),
    );
  }
}

class SshSocks5Greeting {
  SshSocks5Greeting({
    List<SshSocks5AuthMethod> methods = const <SshSocks5AuthMethod>[],
  }) : methods = List<SshSocks5AuthMethod>.unmodifiable(methods);

  factory SshSocks5Greeting.decode(List<int> bytes) {
    final _ByteReader reader = _ByteReader(bytes);
    _expectSocksVersion(reader.readByte());
    final int methodCount = reader.readByte();
    final List<SshSocks5AuthMethod> methods = <SshSocks5AuthMethod>[];
    for (int index = 0; index < methodCount; index += 1) {
      methods.add(SshSocks5AuthMethod.fromCode(reader.readByte()));
    }
    reader.expectDone();
    return SshSocks5Greeting(methods: methods);
  }

  final List<SshSocks5AuthMethod> methods;

  Uint8List encode() {
    final _ByteWriter writer = _ByteWriter()
      ..writeByte(5)
      ..writeByte(methods.length);
    for (final SshSocks5AuthMethod method in methods) {
      writer.writeByte(method.code);
    }
    return writer.toBytes();
  }
}

class SshSocks5MethodSelection {
  const SshSocks5MethodSelection({required this.method});

  factory SshSocks5MethodSelection.decode(List<int> bytes) {
    final _ByteReader reader = _ByteReader(bytes);
    _expectSocksVersion(reader.readByte());
    final SshSocks5MethodSelection selection = SshSocks5MethodSelection(
      method: SshSocks5AuthMethod.fromCode(reader.readByte()),
    );
    reader.expectDone();
    return selection;
  }

  final SshSocks5AuthMethod method;

  Uint8List encode() {
    final _ByteWriter writer = _ByteWriter()
      ..writeByte(5)
      ..writeByte(method.code);
    return writer.toBytes();
  }
}

class SshSocks5Address {
  SshSocks5Address.domain(String host)
      : this._(
          type: SshSocks5AddressType.domainName,
          host: host,
          addressBytes: _encodeDomain(host),
        );

  SshSocks5Address.ipv4(String host)
      : this._(
          type: SshSocks5AddressType.ipv4,
          host: host,
          addressBytes: _encodeIpv4(host),
        );

  SshSocks5Address.ipv6Bytes({
    required List<int> addressBytes,
    String? host,
  }) : this._(
          type: SshSocks5AddressType.ipv6,
          host: host ?? _formatIpv6(addressBytes),
          addressBytes: addressBytes,
        );

  SshSocks5Address._({
    required this.type,
    required this.host,
    required List<int> addressBytes,
  }) : addressBytes = Uint8List.fromList(addressBytes);

  factory SshSocks5Address.decode(_ByteReader reader) {
    final SshSocks5AddressType type = SshSocks5AddressType.fromCode(
      reader.readByte(),
    );
    return switch (type) {
      SshSocks5AddressType.ipv4 => SshSocks5Address.ipv4(
          _decodeIpv4(reader.readBytes(4)),
        ),
      SshSocks5AddressType.domainName => SshSocks5Address.domain(
          String.fromCharCodes(reader.readLengthPrefixedBytes()),
        ),
      SshSocks5AddressType.ipv6 => SshSocks5Address.ipv6Bytes(
          addressBytes: reader.readBytes(16),
        ),
    };
  }

  final SshSocks5AddressType type;
  final String host;
  final Uint8List addressBytes;

  void encode(_ByteWriter writer) {
    writer.writeByte(type.code);
    switch (type) {
      case SshSocks5AddressType.ipv4:
      case SshSocks5AddressType.ipv6:
        writer.writeBytes(addressBytes);
      case SshSocks5AddressType.domainName:
        writer.writeLengthPrefixedBytes(addressBytes);
    }
  }
}

class SshSocks5Request {
  const SshSocks5Request({
    required this.command,
    required this.destinationAddress,
    required this.destinationPort,
  });

  factory SshSocks5Request.decode(List<int> bytes) {
    final _ByteReader reader = _ByteReader(bytes);
    _expectSocksVersion(reader.readByte());
    final SshSocks5Command command =
        SshSocks5Command.fromCode(reader.readByte());
    if (reader.readByte() != 0) {
      throw const FormatException('SOCKS5 reserved byte must be zero.');
    }
    final SshSocks5Request request = SshSocks5Request(
      command: command,
      destinationAddress: SshSocks5Address.decode(reader),
      destinationPort: reader.readUint16(),
    );
    reader.expectDone();
    return request;
  }

  final SshSocks5Command command;
  final SshSocks5Address destinationAddress;
  final int destinationPort;

  Uint8List encode() {
    final _ByteWriter writer = _ByteWriter()
      ..writeByte(5)
      ..writeByte(command.code)
      ..writeByte(0);
    destinationAddress.encode(writer);
    writer.writeUint16(destinationPort);
    return writer.toBytes();
  }
}

class SshSocks5Reply {
  const SshSocks5Reply({
    required this.replyCode,
    required this.boundAddress,
    required this.boundPort,
  });

  factory SshSocks5Reply.decode(List<int> bytes) {
    final _ByteReader reader = _ByteReader(bytes);
    _expectSocksVersion(reader.readByte());
    final SshSocks5ReplyCode replyCode = SshSocks5ReplyCode.fromCode(
      reader.readByte(),
    );
    if (reader.readByte() != 0) {
      throw const FormatException('SOCKS5 reserved byte must be zero.');
    }
    final SshSocks5Reply reply = SshSocks5Reply(
      replyCode: replyCode,
      boundAddress: SshSocks5Address.decode(reader),
      boundPort: reader.readUint16(),
    );
    reader.expectDone();
    return reply;
  }

  final SshSocks5ReplyCode replyCode;
  final SshSocks5Address boundAddress;
  final int boundPort;

  Uint8List encode() {
    final _ByteWriter writer = _ByteWriter()
      ..writeByte(5)
      ..writeByte(replyCode.code)
      ..writeByte(0);
    boundAddress.encode(writer);
    writer.writeUint16(boundPort);
    return writer.toBytes();
  }
}

class _ByteWriter {
  final BytesBuilder _builder = BytesBuilder(copy: false);

  void writeByte(int value) {
    RangeError.checkValueInInterval(value, 0, 255, 'value');
    _builder.add(<int>[value]);
  }

  void writeBytes(List<int> value) {
    _builder.add(value);
  }

  void writeLengthPrefixedBytes(List<int> value) {
    writeByte(value.length);
    writeBytes(value);
  }

  void writeUint16(int value) {
    RangeError.checkValueInInterval(value, 0, 0xFFFF, 'value');
    _builder.add(<int>[(value >> 8) & 0xFF, value & 0xFF]);
  }

  Uint8List toBytes() => _builder.takeBytes();
}

class _ByteReader {
  _ByteReader(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;
  int _offset = 0;

  int get remainingByteCount => _bytes.length - _offset;

  int readByte() {
    _requireAvailable(1);
    return _bytes[_offset++];
  }

  Uint8List readBytes(int length) {
    RangeError.checkNotNegative(length, 'length');
    _requireAvailable(length);
    final Uint8List bytes = Uint8List.fromList(
      _bytes.sublist(_offset, _offset + length),
    );
    _offset += length;
    return bytes;
  }

  Uint8List readLengthPrefixedBytes() {
    return readBytes(readByte());
  }

  int readUint16() {
    _requireAvailable(2);
    final int value = (_bytes[_offset] << 8) | _bytes[_offset + 1];
    _offset += 2;
    return value;
  }

  void expectDone() {
    if (remainingByteCount != 0) {
      throw FormatException(
        'SOCKS5 payload had $remainingByteCount trailing bytes.',
      );
    }
  }

  void _requireAvailable(int length) {
    if (remainingByteCount < length) {
      throw FormatException(
        'SOCKS5 payload ended early. Needed $length bytes, '
        'but only $remainingByteCount remain.',
      );
    }
  }
}

void _expectSocksVersion(int version) {
  if (version != 5) {
    throw FormatException('Expected SOCKS5 version 5, received $version.');
  }
}

Uint8List _encodeDomain(String host) {
  final Uint8List encoded = Uint8List.fromList(host.codeUnits);
  if (encoded.length > 255) {
    throw ArgumentError.value(
      host,
      'host',
      'SOCKS5 domain names must be 255 bytes or shorter.',
    );
  }
  return encoded;
}

Uint8List _encodeIpv4(String host) {
  final List<String> segments = host.split('.');
  if (segments.length != 4) {
    throw ArgumentError.value(host, 'host', 'Invalid IPv4 address.');
  }

  return Uint8List.fromList(
    segments.map((String segment) {
      final int? value = int.tryParse(segment);
      if (value == null || value < 0 || value > 255) {
        throw ArgumentError.value(host, 'host', 'Invalid IPv4 address.');
      }
      return value;
    }).toList(growable: false),
  );
}

String _decodeIpv4(List<int> bytes) {
  return bytes.join('.');
}

String _formatIpv6(List<int> bytes) {
  if (bytes.length != 16) {
    throw ArgumentError.value(
      bytes,
      'addressBytes',
      'SOCKS5 IPv6 addresses must be 16 bytes long.',
    );
  }

  final List<String> groups = <String>[];
  for (int index = 0; index < bytes.length; index += 2) {
    groups.add(
      ((bytes[index] << 8) | bytes[index + 1]).toRadixString(16),
    );
  }
  return groups.join(':');
}
