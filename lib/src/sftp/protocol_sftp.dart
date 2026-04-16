import 'dart:async';
import 'dart:typed_data';

import '../channels/channel.dart';
import '../channels/packet_channel.dart';
import '../sessions/protocol.dart';
import 'protocol.dart';
import 'sftp.dart';

class SshProtocolSftpSubsystem implements SftpSubsystem {
  const SshProtocolSftpSubsystem({
    required this.channelFactory,
    this.protocolVersion = 3,
  });

  final SshPacketChannelFactory channelFactory;
  final int protocolVersion;

  @override
  Future<SftpClient> open() async {
    final SshPacketChannel channel = await channelFactory.openSessionChannel();
    try {
      await channel.sendRequest(
        SshChannelRequest(
          type: 'subsystem',
          wantReply: true,
          payload: <String, Object?>{
            'encodedPayload':
                const SshSubsystemChannelRequest(subsystem: 'sftp').encode(),
          },
        ),
      );
      final SshProtocolSftpClient client = SshProtocolSftpClient._(
        channel: channel,
      );
      await client._initialize(protocolVersion: protocolVersion);
      return client;
    } catch (_) {
      await channel.close();
      rethrow;
    }
  }
}

class SshProtocolSftpClient implements SftpClient {
  SshProtocolSftpClient._({required SshPacketChannel channel})
      : _channel = channel,
        _stdoutIterator = StreamIterator<List<int>>(channel.stdout);

  final SshPacketChannel _channel;
  final StreamIterator<List<int>> _stdoutIterator;
  final SftpPacketCodec _packetCodec = const SftpPacketCodec();
  final List<int> _frameBuffer = <int>[];
  int _nextRequestId = 1;
  Future<void> _pendingOperation = Future<void>.value();
  bool _closed = false;

  Future<void> _initialize({required int protocolVersion}) {
    return _runExclusive(() async {
      await _channel.sendData(
        _packetCodec
            .encode(SftpInitMessage(version: protocolVersion).toPacket()),
      );
      final SftpPacket versionPacket = await _readPacket();
      if (versionPacket.type != SftpPacketType.version) {
        throw StateError(
          'Expected SSH_FXP_VERSION during SFTP init, '
          'received ${versionPacket.type.name}.',
        );
      }
      SftpVersionMessage.decodePayload(versionPacket.payload);
    });
  }

  @override
  Future<List<SftpFileEntry>> listDirectory(String path) {
    return _runExclusive(() => _listDirectoryInternal(path));
  }

  @override
  Future<List<int>> readFile(String path) {
    return _runExclusive(() async {
      final Uint8List handle = await _openHandle(
        type: SftpPacketType.open,
        payload: SftpOpenRequest(
          filename: path,
          pflags: _sftpOpenReadFlag,
        ).encodePayload(),
      );
      final BytesBuilder builder = BytesBuilder(copy: false);
      int offset = 0;
      try {
        for (;;) {
          final SftpPacket response = await _sendRequest(
            type: SftpPacketType.read,
            payload: SftpReadRequest(
              handle: handle,
              offset: offset,
              length: 32768,
            ).encodePayload(),
          );
          if (response.type == SftpPacketType.data) {
            final SftpDataMessage data = SftpDataMessage.decodePayload(
              response.payload,
            );
            builder.add(data.data);
            offset += data.data.length;
            continue;
          }

          final SftpStatusMessage status = _expectStatus(response);
          if (status.code == SftpStatusCode.eof) {
            break;
          }
          _throwForStatus(status, operation: 'read');
        }
        return builder.takeBytes();
      } finally {
        await _closeHandle(handle);
      }
    });
  }

  @override
  Future<void> writeFile(String path, List<int> bytes) {
    return _runExclusive(() async {
      final Uint8List handle = await _openHandle(
        type: SftpPacketType.open,
        payload: SftpOpenRequest(
          filename: path,
          pflags:
              _sftpOpenWriteFlag | _sftpOpenCreateFlag | _sftpOpenTruncateFlag,
        ).encodePayload(),
      );
      int offset = 0;
      try {
        while (offset < bytes.length) {
          final int end =
              (offset + 32768 < bytes.length) ? offset + 32768 : bytes.length;
          final SftpStatusMessage status = _expectStatus(
            await _sendRequest(
              type: SftpPacketType.write,
              payload: SftpWriteRequest(
                handle: handle,
                offset: offset,
                data: bytes.sublist(offset, end),
              ).encodePayload(),
            ),
          );
          _throwForStatus(status, operation: 'write');
          offset = end;
        }
      } finally {
        await _closeHandle(handle);
      }
    });
  }

  @override
  Future<void> createDirectory(String path, {bool recursive = false}) {
    return _runExclusive(() async {
      if (!recursive) {
        final SftpStatusMessage status = _expectStatus(
          await _sendRequest(
            type: SftpPacketType.mkdir,
            payload: SftpPathRequest(
              path: path,
              type: SftpPacketType.mkdir,
            ).encodePayload(),
          ),
        );
        _throwForStatus(status, operation: 'mkdir');
        return;
      }

      String currentPath = path.startsWith('/') ? '/' : '';
      for (final String segment
          in path.split('/').where((String s) => s.isNotEmpty)) {
        currentPath = currentPath == '/'
            ? '/$segment'
            : _joinRemotePath(currentPath, segment);
        final SftpStatusMessage status = _expectStatus(
          await _sendRequest(
            type: SftpPacketType.mkdir,
            payload: SftpPathRequest(
              path: currentPath,
              type: SftpPacketType.mkdir,
            ).encodePayload(),
          ),
        );
        if (status.code != SftpStatusCode.ok &&
            status.code != SftpStatusCode.failure) {
          _throwForStatus(status, operation: 'mkdir');
        }
      }
    });
  }

  @override
  Future<void> delete(String path, {bool recursive = false}) {
    return _runExclusive(() => _deleteInternal(path, recursive: recursive));
  }

  @override
  Future<void> close() async {
    if (_closed) {
      return;
    }

    _closed = true;
    await _channel.sendEof();
    await _channel.close();
  }

  Future<void> _deleteLeaf(String path) async {
    final SftpStatusMessage status = _expectStatus(
      await _sendRequest(
        type: SftpPacketType.remove,
        payload: SftpPathRequest(
          path: path,
          type: SftpPacketType.remove,
        ).encodePayload(),
      ),
    );
    _throwForStatus(status, operation: 'remove');
  }

  Future<Uint8List> _openHandle({
    required SftpPacketType type,
    required List<int> payload,
  }) async {
    final SftpPacket response =
        await _sendRequest(type: type, payload: payload);
    if (response.type == SftpPacketType.handle) {
      return SftpHandleMessage.decodePayload(response.payload).handle;
    }
    final SftpStatusMessage status = _expectStatus(response);
    _throwForStatus(status, operation: 'open');
    throw StateError('Unreachable.');
  }

  Future<void> _closeHandle(List<int> handle) async {
    final SftpStatusMessage status = _expectStatus(
      await _sendRequest(
        type: SftpPacketType.close,
        payload: SftpCloseRequest(handle: handle).encodePayload(),
      ),
    );
    _throwForStatus(status, operation: 'close');
  }

  SftpStatusMessage _expectStatus(SftpPacket packet) {
    if (packet.type != SftpPacketType.status) {
      throw StateError(
        'Expected SFTP status response, received ${packet.type.name}.',
      );
    }
    return SftpStatusMessage.decodePayload(packet.payload);
  }

  void _throwForStatus(SftpStatusMessage status, {required String operation}) {
    if (status.code == SftpStatusCode.ok) {
      return;
    }
    throw StateError(
        'SFTP $operation failed: ${status.code.name} ${status.message}');
  }

  Future<SftpPacket> _sendRequest({
    required SftpPacketType type,
    required List<int> payload,
  }) async {
    final int requestId = _nextRequestId++;
    await _channel.sendData(
      _packetCodec.encode(
        SftpPacket(type: type, requestId: requestId, payload: payload),
      ),
    );
    final SftpPacket response = await _readPacket();
    if (response.requestId != requestId) {
      throw StateError(
        'Expected SFTP response for request $requestId, '
        'received ${response.requestId}.',
      );
    }
    return response;
  }

  Future<SftpPacket> _readPacket() async {
    for (;;) {
      if (_frameBuffer.length >= 4) {
        final int frameLength = (_frameBuffer[0] << 24) |
            (_frameBuffer[1] << 16) |
            (_frameBuffer[2] << 8) |
            _frameBuffer[3];
        final int totalLength = frameLength + 4;
        if (_frameBuffer.length >= totalLength) {
          final List<int> frameBytes = _frameBuffer.sublist(0, totalLength);
          _frameBuffer.removeRange(0, totalLength);
          return _packetCodec.decode(frameBytes);
        }
      }

      if (!await _stdoutIterator.moveNext()) {
        throw StateError('SFTP channel closed before a packet was received.');
      }
      _frameBuffer.addAll(_stdoutIterator.current);
    }
  }

  Future<T> _runExclusive<T>(Future<T> Function() action) {
    final Completer<T> completer = Completer<T>();
    _pendingOperation = _pendingOperation.then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Future<List<SftpFileEntry>> _listDirectoryInternal(String path) async {
    final Uint8List handle = await _openHandle(
      type: SftpPacketType.opendir,
      payload: SftpPathRequest(path: path, type: SftpPacketType.opendir)
          .encodePayload(),
    );
    try {
      final List<SftpFileEntry> entries = <SftpFileEntry>[];
      for (;;) {
        final SftpPacket response = await _sendRequest(
          type: SftpPacketType.readdir,
          payload: SftpHandleRequest(
            type: SftpPacketType.readdir,
            handle: handle,
          ).encodePayload(),
        );
        if (response.type == SftpPacketType.name) {
          final SftpNameMessage names = SftpNameMessage.decodePayload(
            response.payload,
          );
          entries.addAll(
            names.entries
                .where((SftpNameEntry entry) =>
                    entry.filename != '.' && entry.filename != '..')
                .map(
                  (SftpNameEntry entry) => SftpFileEntry(
                    path: _joinRemotePath(path, entry.filename),
                    type: _inferFileType(entry.attributes),
                    size: entry.attributes.size,
                    modifiedAt:
                        _dateTimeFromUnix(entry.attributes.modifiedTime),
                  ),
                ),
          );
          continue;
        }

        final SftpStatusMessage status = _expectStatus(response);
        if (status.code == SftpStatusCode.eof) {
          break;
        }
        _throwForStatus(status, operation: 'readdir');
      }
      return entries;
    } finally {
      await _closeHandle(handle);
    }
  }

  Future<void> _deleteInternal(String path, {required bool recursive}) async {
    if (recursive) {
      final List<SftpFileEntry> entries = await _listDirectoryInternal(path);
      for (final SftpFileEntry entry in entries) {
        if (entry.type == SftpFileType.directory) {
          await _deleteInternal(entry.path, recursive: true);
        } else {
          await _deleteLeaf(entry.path);
        }
      }
    }

    try {
      await _deleteLeaf(path);
    } on StateError {
      final SftpStatusMessage status = _expectStatus(
        await _sendRequest(
          type: SftpPacketType.rmdir,
          payload: SftpPathRequest(
            path: path,
            type: SftpPacketType.rmdir,
          ).encodePayload(),
        ),
      );
      _throwForStatus(status, operation: 'rmdir');
    }
  }
}

SftpFileType _inferFileType(SftpFileAttributes attributes) {
  final int? permissions = attributes.permissions;
  if (permissions == null) {
    return SftpFileType.unknown;
  }

  switch (permissions & 0xF000) {
    case 0x8000:
      return SftpFileType.file;
    case 0x4000:
      return SftpFileType.directory;
    case 0xA000:
      return SftpFileType.symlink;
    default:
      return SftpFileType.special;
  }
}

DateTime? _dateTimeFromUnix(int? unixTimestamp) {
  if (unixTimestamp == null) {
    return null;
  }
  return DateTime.fromMillisecondsSinceEpoch(unixTimestamp * 1000, isUtc: true);
}

String _joinRemotePath(String parent, String child) {
  if (parent.isEmpty || parent == '.') {
    return child;
  }
  if (parent.endsWith('/')) {
    return '$parent$child';
  }
  return '$parent/$child';
}

const int _sftpOpenReadFlag = 0x00000001;
const int _sftpOpenWriteFlag = 0x00000002;
const int _sftpOpenCreateFlag = 0x00000008;
const int _sftpOpenTruncateFlag = 0x00000010;
