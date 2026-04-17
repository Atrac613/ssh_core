import 'dart:async';
import 'dart:collection';

import 'package:ssh_core/ssh_core.dart';
import 'package:test/test.dart';

void main() {
  group('SshUserAuthProtocolAuthenticator', () {
    test('ignores SSH_MSG_EXT_INFO during service negotiation and auth',
        () async {
      final _ScriptedPacketTransport transport = _ScriptedPacketTransport(
        scriptedPackets: <List<int>>[
          SshExtInfoMessage(
            entries: const <String, String>{'server-sig-algs': 'ssh-ed25519'},
          ).encodePayload(),
          SshServiceAcceptMessage(serviceName: sshUserauthService)
              .encodePayload(),
          SshExtInfoMessage(
            entries: const <String, String>{'server-sig-algs': 'ssh-ed25519'},
          ).encodePayload(),
          SshUserAuthFailureMessage(
            allowedMethods: const <String>['password'],
            partialSuccess: false,
          ).encodePayload(),
        ],
      );

      final SshAuthResult result =
          await const SshUserAuthProtocolAuthenticator().authenticate(
        context: SshAuthContext(
          config: const SshClientConfig(host: 'example.com', username: 'demo'),
          transport: transport,
          handshake: const SshHandshakeInfo(
            localIdentification: 'SSH-2.0-shellway',
            remoteIdentification: 'SSH-2.0-test',
          ),
        ),
        methods: const <SshAuthMethod>[SshPasswordAuthMethod(password: 'pw')],
      );

      expect(result.isSuccess, isFalse);
      expect(result.allowedMethods, contains('password'));
      expect(transport.writtenPayloads, hasLength(2));
      expect(
        SshServiceRequestMessage.decodePayload(transport.writtenPayloads[0])
            .serviceName,
        sshUserauthService,
      );
      expect(
        SshUserAuthRequestMessage.decodePayload(transport.writtenPayloads[1])
            .methodName,
        'password',
      );
    });
  });
}

class _ScriptedPacketTransport implements SshPacketTransport {
  _ScriptedPacketTransport({required List<List<int>> scriptedPackets})
      : _scriptedPackets = Queue<List<int>>.of(scriptedPackets);

  final Queue<List<int>> _scriptedPackets;
  final List<List<int>> writtenPayloads = <List<int>>[];

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
  Future<void> disconnect() async {}

  @override
  Future<SshBinaryPacket> readPacket() async {
    if (_scriptedPackets.isEmpty) {
      throw StateError('No more packets.');
    }

    return SshBinaryPacket(
      payload: _scriptedPackets.removeFirst(),
      padding: const <int>[],
    );
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {
    throw UnimplementedError();
  }

  @override
  Future<void> writeBytes(List<int> bytes) async {
    writtenPayloads.add(List<int>.from(bytes));
  }

  @override
  Future<void> writePacket(List<int> payload) async {
    writtenPayloads.add(List<int>.from(payload));
  }
}
