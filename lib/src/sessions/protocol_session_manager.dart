import 'dart:async';

import '../channels/channel.dart';
import '../channels/packet_channel.dart';
import '../pty/pty.dart';
import 'protocol.dart';
import 'session.dart';

class SshProtocolSessionManager implements SshSessionManager {
  const SshProtocolSessionManager({required this.channelFactory});

  final SshPacketChannelFactory channelFactory;

  @override
  Future<SshShellSession> openShellSession(SshShellRequest request) async {
    final SshPacketChannel channel = await channelFactory.openSessionChannel();
    try {
      for (final MapEntry<String, String> environmentEntry
          in request.environment.entries) {
        await channel.sendRequest(
          SshChannelRequest(
            type: 'env',
            payload: <String, Object?>{
              'encodedPayload': SshEnvChannelRequest(
                name: environmentEntry.key,
                value: environmentEntry.value,
              ).encode(),
            },
          ),
        );
      }

      final SshPtyConfig? pty = request.pty;
      if (pty != null) {
        await channel.sendRequest(
          SshChannelRequest(
            type: 'pty-req',
            wantReply: true,
            payload: <String, Object?>{
              'encodedPayload': SshPtyChannelRequest(pty: pty).encode(),
            },
          ),
        );
      }

      await channel.sendRequest(
        const SshChannelRequest(type: 'shell', wantReply: true),
      );
      return SshProtocolShellSession._(channel);
    } catch (_) {
      await channel.close();
      rethrow;
    }
  }
}

class SshProtocolShellSession implements SshShellSession {
  SshProtocolShellSession._(this._channel) {
    unawaited(
      _channel.done.then((_) {
        _state = SshSessionState.closed;
      }),
    );
  }

  final SshPacketChannel _channel;
  SshSessionState _state = SshSessionState.active;

  @override
  SshChannel get channel => _channel;

  @override
  SshSessionState get state => _state;

  @override
  Stream<List<int>> get stdout => _channel.stdout;

  @override
  Stream<List<int>> get stderr => _channel.stderr;

  @override
  Future<void> writeStdin(List<int> data) => _channel.sendData(data);

  @override
  Future<void> resizePty(SshPtyConfig nextPty) {
    return _channel.sendRequest(
      SshChannelRequest(
        type: 'window-change',
        payload: <String, Object?>{
          'encodedPayload': SshWindowChangeChannelRequest(
            columns: nextPty.columns,
            rows: nextPty.rows,
            pixelWidth: nextPty.pixelWidth,
            pixelHeight: nextPty.pixelHeight,
          ).encode(),
        },
      ),
    );
  }

  @override
  Future<void> close() async {
    if (_state == SshSessionState.closed || _state == SshSessionState.closing) {
      return;
    }

    _state = SshSessionState.closing;
    await _channel.sendEof();
    await _channel.close();
    await _channel.done;
    _state = SshSessionState.closed;
  }
}
