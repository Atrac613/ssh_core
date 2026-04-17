import 'dart:async';

import 'package:ssh_core/ssh_core.dart';
import 'package:test/test.dart';

void main() {
  group('SshTransportStream.readPacket', () {
    test('surfaces SSH disconnect messages as SshDisconnectException',
        () async {
      final SshPacketCodec codec = const SshPacketCodec();
      final SshTransportStream transportStream = SshTransportStream(
        incoming: Stream<List<int>>.fromIterable(<List<int>>[
          codec.encode(
            const SshDisconnectMessage(
              reasonCode: 11,
              description: 'Disconnected by application.',
              languageTag: 'en',
            ).encodePayload(),
          ),
        ]),
        onWrite: (_) async {},
      );
      addTearDown(transportStream.close);

      await expectLater(
        transportStream.readPacket(),
        throwsA(
          isA<SshDisconnectException>()
              .having((SshDisconnectException error) => error.reasonCode,
                  'reasonCode', 11)
              .having((SshDisconnectException error) => error.description,
                  'description', 'Disconnected by application.')
              .having((SshDisconnectException error) => error.languageTag,
                  'languageTag', 'en'),
        ),
      );
    });
  });
}
