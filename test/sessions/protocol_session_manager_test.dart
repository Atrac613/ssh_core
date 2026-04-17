import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:ssh_core/ssh_core.dart';
import 'package:test/test.dart';

void main() {
  group('SshProtocolSessionManager', () {
    test(
      'opens a shell session with env and PTY before shell request',
      () async {
        final _ScriptedPacketTransport transport = _ScriptedPacketTransport(
          scriptedPackets: <List<int>>[
            SshChannelOpenConfirmationMessage(
              recipientChannel: 0,
              senderChannel: 51,
              initialWindowSize: 65536,
              maximumPacketSize: 32768,
            ).encodePayload(),
            const SshChannelSuccessMessage(recipientChannel: 0).encodePayload(),
            const SshChannelSuccessMessage(recipientChannel: 0).encodePayload(),
            const SshChannelEofMessage(recipientChannel: 0).encodePayload(),
            const SshChannelCloseMessage(recipientChannel: 0).encodePayload(),
          ],
        );
        final SshProtocolSessionManager manager = SshProtocolSessionManager(
          channelFactory: SshPacketChannelFactory(transport: transport),
        );

        final SshShellSession session = await manager.openShellSession(
          SshShellRequest(
            pty: const SshPtyConfig(columns: 100, rows: 30),
            environment: const <String, String>{'LANG': 'C.UTF-8'},
          ),
        );

        expect(session.state, SshSessionState.active);
        expect(transport.writtenPayloads, hasLength(4));

        final SshChannelOpenMessage openMessage =
            SshChannelOpenMessage.decodePayload(transport.writtenPayloads[0]);
        expect(openMessage.channelType, 'session');

        final SshChannelRequestMessage envMessage =
            SshChannelRequestMessage.decodePayload(
          transport.writtenPayloads[1],
        );
        expect(envMessage.requestType, 'env');
        expect(
          SshEnvChannelRequest.decode(envMessage.requestData).value,
          'C.UTF-8',
        );

        final SshChannelRequestMessage ptyMessage =
            SshChannelRequestMessage.decodePayload(
          transport.writtenPayloads[2],
        );
        expect(ptyMessage.requestType, 'pty-req');
        expect(
          SshPtyChannelRequest.decode(ptyMessage.requestData).pty.columns,
          100,
        );

        final SshChannelRequestMessage shellMessage =
            SshChannelRequestMessage.decodePayload(
          transport.writtenPayloads[3],
        );
        expect(shellMessage.requestType, 'shell');

        await session.stdout.drain<void>();
        await transport.disconnect();
      },
    );

    test('writes stdin and sends PTY resize requests', () async {
      final _ScriptedPacketTransport transport = _ScriptedPacketTransport(
        scriptedPackets: <List<int>>[
          SshChannelOpenConfirmationMessage(
            recipientChannel: 0,
            senderChannel: 61,
            initialWindowSize: 65536,
            maximumPacketSize: 32768,
          ).encodePayload(),
          const SshChannelSuccessMessage(recipientChannel: 0).encodePayload(),
          SshChannelDataMessage(
            recipientChannel: 0,
            data: utf8.encode('ready'),
          ).encodePayload(),
          const SshChannelEofMessage(recipientChannel: 0).encodePayload(),
          const SshChannelCloseMessage(recipientChannel: 0).encodePayload(),
        ],
      );
      final SshProtocolSessionManager manager = SshProtocolSessionManager(
        channelFactory: SshPacketChannelFactory(transport: transport),
      );
      final SshShellSession session = await manager.openShellSession(
        const SshShellRequest(),
      );

      await session.writeStdin(utf8.encode('pwd\n'));
      await session.resizePty(const SshPtyConfig(columns: 120, rows: 40));
      final List<List<int>> stdoutChunks = await session.stdout.toList();

      expect(stdoutChunks, hasLength(1));
      expect(utf8.decode(stdoutChunks.single), 'ready');
      expect(transport.writtenPayloads, hasLength(4));

      final SshChannelDataMessage stdinMessage =
          SshChannelDataMessage.decodePayload(transport.writtenPayloads[2]);
      expect(utf8.decode(stdinMessage.data), 'pwd\n');

      final SshChannelRequestMessage resizeMessage =
          SshChannelRequestMessage.decodePayload(transport.writtenPayloads[3]);
      expect(resizeMessage.requestType, 'window-change');
      expect(
        SshWindowChangeChannelRequest.decode(resizeMessage.requestData).columns,
        120,
      );

      await transport.disconnect();
    });
  });
}

class _ScriptedPacketTransport implements SshPacketTransport {
  _ScriptedPacketTransport({required List<List<int>> scriptedPackets})
      : _scriptedPackets = Queue<List<int>>.of(scriptedPackets);

  final Queue<List<int>> _scriptedPackets;
  final List<List<int>> writtenPayloads = <List<int>>[];
  final Completer<void> _disconnectCompleter = Completer<void>();

  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    throw UnimplementedError();
  }

  @override
  Future<void> disconnect() async {
    if (_disconnectCompleter.isCompleted) {
      return;
    }
    _disconnectCompleter.complete();
  }

  @override
  Future<SshBinaryPacket> readPacket() async {
    if (_scriptedPackets.isEmpty) {
      await _disconnectCompleter.future;
      throw StateError('Transport closed.');
    }

    final List<int> payload = _scriptedPackets.removeFirst();
    return SshBinaryPacket(
      payload: Uint8List.fromList(payload),
      padding: Uint8List(0),
    );
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {
    throw UnimplementedError();
  }

  @override
  Future<void> writeBytes(List<int> bytes) async {
    throw UnimplementedError();
  }

  @override
  Future<void> writePacket(List<int> payload) async {
    writtenPayloads.add(List<int>.from(payload));
  }
}
