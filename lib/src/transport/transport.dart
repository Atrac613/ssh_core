import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'host_key.dart';

class SshEndpoint {
  const SshEndpoint({required this.host, this.port = 22});

  final String host;
  final int port;
}

class SshTransportSettings {
  const SshTransportSettings({
    this.connectTimeout = const Duration(seconds: 10),
    this.keepAliveInterval,
    this.clientIdentification = 'SSH-2.0-ssh_core',
  });

  final Duration connectTimeout;
  final Duration? keepAliveInterval;
  final String clientIdentification;
}

enum SshTransportState { disconnected, connecting, connected, closed }

class SshHandshakeInfo {
  const SshHandshakeInfo({
    required this.localIdentification,
    required this.remoteIdentification,
    this.negotiatedAlgorithms = const <String, String>{},
    this.hostKey,
  });

  factory SshHandshakeInfo.fromBannerExchange(
    SshBannerExchangeResult exchange, {
    Map<String, String> negotiatedAlgorithms = const <String, String>{},
    SshHostKey? hostKey,
  }) {
    return SshHandshakeInfo(
      localIdentification: exchange.localBanner.value,
      remoteIdentification: exchange.remoteBanner.value,
      negotiatedAlgorithms: negotiatedAlgorithms,
      hostKey: hostKey,
    );
  }

  final String localIdentification;
  final String remoteIdentification;
  final Map<String, String> negotiatedAlgorithms;
  final SshHostKey? hostKey;
}

class SshGlobalRequest {
  const SshGlobalRequest({
    required this.type,
    this.wantReply = false,
    this.payload = const <String, Object?>{},
  });

  final String type;
  final bool wantReply;
  final Map<String, Object?> payload;
}

abstract class SshTransport {
  SshTransportState get state;

  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  });

  Future<void> sendGlobalRequest(SshGlobalRequest request);

  Future<void> disconnect();
}

abstract class SshPacketTransport implements SshTransport {
  Future<SshBinaryPacket> readPacket();

  Future<void> writePacket(List<int> payload);

  Future<void> writeBytes(List<int> bytes);
}

class SshTransportBanner {
  SshTransportBanner({
    required this.protocolVersion,
    required this.softwareVersion,
    this.comments,
  }) {
    _validateBannerToken(protocolVersion, fieldName: 'protocol version');
    _validateBannerToken(softwareVersion, fieldName: 'software version');

    final String? bannerComments = comments;
    if (bannerComments != null && bannerComments.isNotEmpty) {
      _validateBannerComments(bannerComments);
    }

    final int encodedLength = utf8.encode(wireLine).length;
    if (encodedLength > 255) {
      throw FormatException(
        'SSH identification line must be 255 bytes or shorter.',
      );
    }
  }

  factory SshTransportBanner.parse(String line) {
    final String normalized = _normalizeBannerLine(line);
    if (!normalized.startsWith('SSH-')) {
      throw const FormatException(
        'SSH identification line must start with "SSH-".',
      );
    }

    final int protocolSeparator = normalized.indexOf('-', 4);
    if (protocolSeparator < 0) {
      throw const FormatException(
        'SSH identification line must contain a protocol version separator.',
      );
    }

    final String protocolVersion = normalized.substring(4, protocolSeparator);
    final String softwareAndComments =
        normalized.substring(protocolSeparator + 1);
    if (softwareAndComments.isEmpty) {
      throw const FormatException(
        'SSH identification line must include a software version.',
      );
    }

    final int commentSeparator = softwareAndComments.indexOf(' ');
    final String softwareVersion;
    final String? comments;

    if (commentSeparator < 0) {
      softwareVersion = softwareAndComments;
      comments = null;
    } else {
      softwareVersion = softwareAndComments.substring(0, commentSeparator);
      final String rawComments = softwareAndComments.substring(
        commentSeparator + 1,
      );
      comments = rawComments.isEmpty ? null : rawComments;
    }

    return SshTransportBanner(
      protocolVersion: protocolVersion,
      softwareVersion: softwareVersion,
      comments: comments,
    );
  }

  final String protocolVersion;
  final String softwareVersion;
  final String? comments;

  String get value {
    final StringBuffer buffer = StringBuffer('SSH-')
      ..write(protocolVersion)
      ..write('-')
      ..write(softwareVersion);

    final String? bannerComments = comments;
    if (bannerComments != null && bannerComments.isNotEmpty) {
      buffer
        ..write(' ')
        ..write(bannerComments);
    }

    return buffer.toString();
  }

  String get wireLine => '$value\r\n';
}

class SshBannerExchangeResult {
  SshBannerExchangeResult({
    required this.localBanner,
    required this.remoteBanner,
    List<String> ignoredLines = const <String>[],
  }) : ignoredLines = List.unmodifiable(ignoredLines);

  final SshTransportBanner localBanner;
  final SshTransportBanner remoteBanner;
  final List<String> ignoredLines;
}

class SshBannerExchange {
  const SshBannerExchange({this.maxPreludeLines = 20})
      : assert(maxPreludeLines >= 0);

  final int maxPreludeLines;

  String formatLocalLine(String identification) {
    return SshTransportBanner.parse(identification).wireLine;
  }

  SshBannerExchangeResult resolve({
    required String localIdentification,
    required Iterable<String> remoteLines,
  }) {
    final SshTransportBanner localBanner = SshTransportBanner.parse(
      localIdentification,
    );
    final List<String> ignoredLines = <String>[];

    for (final String line in remoteLines) {
      final String normalized = _normalizeBannerLine(line);
      if (normalized.startsWith('SSH-')) {
        final SshTransportBanner remoteBanner = SshTransportBanner.parse(
          normalized,
        );
        return SshBannerExchangeResult(
          localBanner: localBanner,
          remoteBanner: remoteBanner,
          ignoredLines: ignoredLines,
        );
      }

      ignoredLines.add(normalized);
      if (ignoredLines.length > maxPreludeLines) {
        throw FormatException(
          'SSH peer sent too many prelude lines before its identification.',
        );
      }
    }

    throw const FormatException(
      'SSH peer did not provide an identification line.',
    );
  }
}

typedef SshPaddingBytesFactory = List<int> Function(int length);

class SshTransportBuffer {
  SshTransportBuffer({
    this.packetCodec = const SshPacketCodec(),
    this.maxLineLength = 255,
  }) : assert(maxLineLength > 0);

  final SshPacketCodec packetCodec;
  final int maxLineLength;
  final List<int> _buffer = <int>[];

  int get pendingByteCount => _buffer.length;

  void add(List<int> bytes) {
    _buffer.addAll(bytes);
  }

  String? readLine() {
    final int lineFeedIndex = _buffer.indexOf(10);
    if (lineFeedIndex < 0) {
      if (_buffer.length > maxLineLength) {
        throw FormatException(
          'SSH line reader exceeded the maximum line length of $maxLineLength.',
        );
      }
      return null;
    }

    if (lineFeedIndex + 1 > maxLineLength) {
      throw FormatException(
        'SSH line reader exceeded the maximum line length of $maxLineLength.',
      );
    }

    final int contentEnd = lineFeedIndex > 0 && _buffer[lineFeedIndex - 1] == 13
        ? lineFeedIndex - 1
        : lineFeedIndex;
    final List<int> lineBytes = _buffer.sublist(0, contentEnd);
    _buffer.removeRange(0, lineFeedIndex + 1);

    return utf8.decode(lineBytes);
  }

  SshBinaryPacket? readPacket() {
    if (_buffer.length < 5) {
      return null;
    }

    final int packetLength = _readUint32(_buffer, 0);
    final int frameLength = packetLength + 4;
    if (_buffer.length < frameLength) {
      return null;
    }

    final List<int> frame = _buffer.sublist(0, frameLength);
    _buffer.removeRange(0, frameLength);
    return packetCodec.decode(frame);
  }
}

class SshLineReader {
  SshLineReader({int maxLineLength = 255})
      : _buffer = SshTransportBuffer(maxLineLength: maxLineLength);

  final SshTransportBuffer _buffer;

  int get maxLineLength => _buffer.maxLineLength;

  int get pendingByteCount => _buffer.pendingByteCount;

  void add(List<int> bytes) {
    _buffer.add(bytes);
  }

  String? readLine() => _buffer.readLine();
}

class SshBinaryPacket {
  SshBinaryPacket({
    required List<int> payload,
    required List<int> padding,
  })  : payload = Uint8List.fromList(payload),
        padding = Uint8List.fromList(padding),
        paddingLength = padding.length,
        packetLength = 1 + payload.length + padding.length;

  final Uint8List payload;
  final Uint8List padding;
  final int paddingLength;
  final int packetLength;

  int get frameLength => 4 + packetLength;

  int? get messageId => payload.isEmpty ? null : payload.first;
}

class SshPacketCodec {
  const SshPacketCodec({
    this.blockSize = 8,
    this.minimumPadding = 4,
    this.paddingBytesFactory = _zeroPadding,
  })  : assert(blockSize >= 8),
        assert(minimumPadding >= 4),
        assert(minimumPadding <= 255);

  final int blockSize;
  final int minimumPadding;
  final SshPaddingBytesFactory paddingBytesFactory;

  Uint8List encode(List<int> payload) {
    final int paddingLength = _resolvePaddingLength(payload.length);
    final List<int> paddingBytes = paddingBytesFactory(paddingLength);
    if (paddingBytes.length != paddingLength) {
      throw StateError(
        'SshPaddingBytesFactory must return exactly $paddingLength bytes.',
      );
    }

    final int packetLength = 1 + payload.length + paddingLength;
    final Uint8List frame = Uint8List(4 + packetLength);
    final ByteData header = ByteData.sublistView(frame);

    header.setUint32(0, packetLength);
    frame[4] = paddingLength;
    frame.setRange(5, 5 + payload.length, payload);
    frame.setRange(5 + payload.length, frame.length, paddingBytes);

    return frame;
  }

  SshBinaryPacket decode(List<int> frameBytes) {
    if (frameBytes.length < 5) {
      throw const FormatException(
        'SSH packet frame must be at least 5 bytes long.',
      );
    }

    final int packetLength = _readUint32(frameBytes, 0);
    final int frameLength = packetLength + 4;
    if (frameLength != frameBytes.length) {
      throw FormatException(
        'SSH packet frame length mismatch: expected $frameLength bytes, '
        'received ${frameBytes.length}.',
      );
    }

    if (frameLength % blockSize != 0) {
      throw FormatException(
        'SSH packet frame length must align to the block size of $blockSize.',
      );
    }

    final int paddingLength = frameBytes[4];
    if (paddingLength < 4) {
      throw const FormatException(
        'SSH packet padding length must be at least 4 bytes.',
      );
    }

    final int payloadLength = packetLength - paddingLength - 1;
    if (payloadLength < 0) {
      throw const FormatException(
        'SSH packet payload length cannot be negative.',
      );
    }

    final int payloadStart = 5;
    final int payloadEnd = payloadStart + payloadLength;
    final int paddingEnd = payloadEnd + paddingLength;

    return SshBinaryPacket(
      payload: frameBytes.sublist(payloadStart, payloadEnd),
      padding: frameBytes.sublist(payloadEnd, paddingEnd),
    );
  }

  int _resolvePaddingLength(int payloadLength) {
    final int baseLength = 4 + 1 + payloadLength;
    int paddingLength = minimumPadding;

    while ((baseLength + paddingLength) % blockSize != 0) {
      paddingLength += 1;
    }

    if (paddingLength > 255) {
      throw StateError('SSH packet padding length exceeded 255 bytes.');
    }

    return paddingLength;
  }
}

class SshPacketReader {
  SshPacketReader({SshPacketCodec codec = const SshPacketCodec()})
      : _buffer = SshTransportBuffer(packetCodec: codec);

  final SshTransportBuffer _buffer;

  SshPacketCodec get codec => _buffer.packetCodec;

  int get pendingByteCount => _buffer.pendingByteCount;

  void add(List<int> bytes) {
    _buffer.add(bytes);
  }

  SshBinaryPacket? read() => _buffer.readPacket();
}

typedef SshTransportWriteCallback = FutureOr<void> Function(List<int> bytes);

typedef SshTransportCloseCallback = FutureOr<void> Function();

class SshTransportStream {
  SshTransportStream({
    required Stream<List<int>> incoming,
    required SshTransportWriteCallback onWrite,
    SshTransportCloseCallback? onClose,
    this.bannerExchange = const SshBannerExchange(),
    SshPacketCodec packetCodec = const SshPacketCodec(),
    int maxLineLength = 255,
  })  : _incoming = StreamIterator<List<int>>(incoming),
        _onWrite = onWrite,
        _onClose = onClose,
        _buffer = SshTransportBuffer(
          packetCodec: packetCodec,
          maxLineLength: maxLineLength,
        );

  final StreamIterator<List<int>> _incoming;
  final SshTransportWriteCallback _onWrite;
  final SshTransportCloseCallback? _onClose;
  final SshTransportBuffer _buffer;
  final SshBannerExchange bannerExchange;

  SshPacketCodec get packetCodec => _buffer.packetCodec;

  int get pendingByteCount => _buffer.pendingByteCount;

  Future<SshBannerExchangeResult> exchangeBanners({
    required String localIdentification,
  }) async {
    await writeBytes(
      utf8.encode(bannerExchange.formatLocalLine(localIdentification)),
    );

    final List<String> remoteLines = <String>[];
    for (;;) {
      final String? line = _buffer.readLine();
      if (line != null) {
        remoteLines.add(line);
        if (line.startsWith('SSH-')) {
          return bannerExchange.resolve(
            localIdentification: localIdentification,
            remoteLines: remoteLines,
          );
        }
        continue;
      }

      if (!await _fillBuffer()) {
        throw StateError(
          'SSH peer closed before sending an identification line.',
        );
      }
    }
  }

  Future<SshBinaryPacket> readPacket() async {
    for (;;) {
      final SshBinaryPacket? packet = _buffer.readPacket();
      if (packet != null) {
        return packet;
      }

      if (!await _fillBuffer()) {
        throw StateError(
          'SSH peer closed before a complete packet was received.',
        );
      }
    }
  }

  Future<void> writePacket(List<int> payload) async {
    await writeBytes(packetCodec.encode(payload));
  }

  Future<void> writeBytes(List<int> bytes) async {
    await Future<void>.value(_onWrite(bytes));
  }

  Future<void> close() async {
    await _incoming.cancel();
    final SshTransportCloseCallback? onClose = _onClose;
    if (onClose != null) {
      await Future<void>.value(onClose());
    }
  }

  Future<bool> _fillBuffer() async {
    final bool hasNext = await _incoming.moveNext();
    if (!hasNext) {
      return false;
    }

    _buffer.add(_incoming.current);
    return true;
  }
}

List<int> _zeroPadding(int length) => List<int>.filled(length, 0);

String _normalizeBannerLine(String line) {
  final String normalized = line.replaceAll('\r', '').replaceAll('\n', '');
  if (normalized.contains('\u0000')) {
    throw const FormatException(
      'SSH identification line must not contain NUL bytes.',
    );
  }
  return normalized;
}

void _validateBannerToken(String value, {required String fieldName}) {
  if (value.isEmpty) {
    throw FormatException('SSH $fieldName must not be empty.');
  }

  for (final int codeUnit in value.codeUnits) {
    if (codeUnit <= 32 || codeUnit == 127) {
      throw FormatException(
        'SSH $fieldName must not contain spaces or control characters.',
      );
    }
  }
}

void _validateBannerComments(String value) {
  for (final int codeUnit in value.codeUnits) {
    if (codeUnit == 0 || codeUnit == 10 || codeUnit == 13) {
      throw const FormatException(
        'SSH identification comments must not contain control characters.',
      );
    }
  }
}

int _readUint32(List<int> bytes, int offset) {
  return (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
}
