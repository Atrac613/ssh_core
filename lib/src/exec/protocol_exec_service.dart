import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../channels/channel.dart';
import '../channels/packet_channel.dart';
import '../channels/protocol.dart';
import '../pty/pty.dart';
import '../sessions/protocol.dart';
import 'exec.dart';

class SshProtocolExecService implements SshExecService {
  const SshProtocolExecService({required this.channelFactory});

  final SshPacketChannelFactory channelFactory;

  @override
  Future<SshExecResult> exec(SshExecRequest request) async {
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

      if (request.forwardAgent) {
        await channel.sendRequest(
          const SshChannelRequest(
            type: 'auth-agent-req@openssh.com',
            wantReply: true,
          ),
        );
      }

      await channel.sendRequest(
        SshChannelRequest(
          type: 'exec',
          wantReply: true,
          payload: <String, Object?>{
            'encodedPayload': SshExecChannelRequest(
              command: request.command,
            ).encode(),
          },
        ),
      );

      final BytesBuilder stdoutBuilder = BytesBuilder(copy: false);
      final BytesBuilder stderrBuilder = BytesBuilder(copy: false);
      final Future<void> stdoutDone = channel.stdout.forEach(stdoutBuilder.add);
      final Future<void> stderrDone = channel.stderr.forEach(stderrBuilder.add);

      int exitCode = 0;
      final StreamSubscription<SshChannelRequestMessage> requestSubscription =
          channel.inboundRequests.listen((SshChannelRequestMessage message) {
        switch (message.requestType) {
          case 'exit-status':
            exitCode = SshExitStatusChannelRequest.decode(
              message.requestData,
            ).exitStatus;
            return;
          case 'exit-signal':
            final SshExitSignalChannelRequest exitSignal =
                SshExitSignalChannelRequest.decode(message.requestData);
            stderrBuilder.add(
              utf8.encode(exitSignal.errorMessage),
            );
            exitCode = 255;
            return;
          default:
            return;
        }
      });

      await channel.done;
      await requestSubscription.cancel();
      await stdoutDone;
      await stderrDone;

      return SshExecResult(
        exitCode: exitCode,
        stdout: stdoutBuilder.takeBytes(),
        stderr: stderrBuilder.takeBytes(),
      );
    } catch (_) {
      await channel.close();
      rethrow;
    }
  }
}
