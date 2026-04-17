import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:ssh_core/ssh_core_io.dart';
import 'package:test/test.dart';

void main() {
  test('routes concurrent remote forwards to the matching targets', () async {
    final ServerSocket targetA = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final ServerSocket targetB = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final Completer<String> targetAInbound = Completer<String>();
    final Completer<String> targetBInbound = Completer<String>();
    final Future<void> targetATask = _acceptTargetConnection(
      server: targetA,
      outboundMessage: 'from-target-a',
      inbound: targetAInbound,
    );
    final Future<void> targetBTask = _acceptTargetConnection(
      server: targetB,
      outboundMessage: 'from-target-b',
      inbound: targetBInbound,
    );

    final _PacketForwardTransport transport = _PacketForwardTransport(
      replies: <SshGlobalRequestReply>[
        SshGlobalRequestReply.success(
          responseData: (SshPayloadWriter()..writeUint32(4100)).toBytes(),
        ),
        SshGlobalRequestReply.success(
          responseData: (SshPayloadWriter()..writeUint32(4200)).toBytes(),
        ),
        SshGlobalRequestReply.success(),
        SshGlobalRequestReply.success(),
      ],
    );
    final SshPacketChannelFactory channelFactory = SshPacketChannelFactory(
      transport: transport,
    );
    final SshIoPortForwardingService service = SshIoPortForwardingService(
      transport: transport,
      channelFactory: channelFactory,
    );

    final SshPortForward forwardA = await service.openForward(
      SshForwardRequest.remote(
        bindHost: InternetAddress.loopbackIPv4.address,
        bindPort: 0,
        target: SshForwardTarget(
          host: InternetAddress.loopbackIPv4.address,
          port: targetA.port,
        ),
      ),
    );
    final SshPortForward forwardB = await service.openForward(
      SshForwardRequest.remote(
        bindHost: InternetAddress.loopbackIPv4.address,
        bindPort: 0,
        target: SshForwardTarget(
          host: InternetAddress.loopbackIPv4.address,
          port: targetB.port,
        ),
      ),
    );

    transport.enqueuePacket(
      SshChannelOpenMessage(
        channelType: sshForwardedTcpIpChannelType,
        senderChannel: 100,
        initialWindowSize: 64 * 1024,
        maximumPacketSize: 32 * 1024,
        channelData: SshForwardedTcpIpChannelOpenData(
          connectedHost: InternetAddress.loopbackIPv4.address,
          connectedPort: forwardA.bindPort,
          originatorHost: InternetAddress.loopbackIPv4.address,
          originatorPort: 5001,
        ).encode(),
      ).encodePayload(),
    );
    transport.enqueuePacket(
      SshChannelOpenMessage(
        channelType: sshForwardedTcpIpChannelType,
        senderChannel: 101,
        initialWindowSize: 64 * 1024,
        maximumPacketSize: 32 * 1024,
        channelData: SshForwardedTcpIpChannelOpenData(
          connectedHost: InternetAddress.loopbackIPv4.address,
          connectedPort: forwardB.bindPort,
          originatorHost: InternetAddress.loopbackIPv4.address,
          originatorPort: 5002,
        ).encode(),
      ).encodePayload(),
    );

    final List<SshChannelDataMessage> outboundMessages =
        await _waitForChannelDataWrites(transport, count: 2);
    expect(outboundMessages, hasLength(2));
    expect(
      outboundMessages.where((SshChannelDataMessage message) {
        return message.recipientChannel == 100 &&
            utf8.decode(message.data) == 'from-target-a';
      }),
      hasLength(1),
    );
    expect(
      outboundMessages.where((SshChannelDataMessage message) {
        return message.recipientChannel == 101 &&
            utf8.decode(message.data) == 'from-target-b';
      }),
      hasLength(1),
    );

    transport.enqueuePacket(
      SshChannelDataMessage(
        recipientChannel: 0,
        data: utf8.encode('to-target-a'),
      ).encodePayload(),
    );
    transport.enqueuePacket(
      SshChannelDataMessage(
        recipientChannel: 1,
        data: utf8.encode('to-target-b'),
      ).encodePayload(),
    );

    expect(await targetAInbound.future, 'to-target-a');
    expect(await targetBInbound.future, 'to-target-b');

    transport.enqueuePacket(
      SshChannelEofMessage(recipientChannel: 0).encodePayload(),
    );
    transport.enqueuePacket(
      SshChannelCloseMessage(recipientChannel: 0).encodePayload(),
    );
    transport.enqueuePacket(
      SshChannelEofMessage(recipientChannel: 1).encodePayload(),
    );
    transport.enqueuePacket(
      SshChannelCloseMessage(recipientChannel: 1).encodePayload(),
    );

    await forwardA.close();
    await forwardB.close();
    await targetATask;
    await targetBTask;
    await targetA.close();
    await targetB.close();
    await transport.close();
  });
}

Future<void> _acceptTargetConnection({
  required ServerSocket server,
  required String outboundMessage,
  required Completer<String> inbound,
}) async {
  final Socket socket = await server.first;
  final StreamIterator<List<int>> iterator = StreamIterator<List<int>>(socket);
  try {
    socket.add(utf8.encode(outboundMessage));
    await socket.flush();

    if (await iterator.moveNext()) {
      if (!inbound.isCompleted) {
        inbound.complete(utf8.decode(iterator.current));
      }
    }
  } finally {
    await iterator.cancel();
    await socket.close();
    socket.destroy();
  }
}

Future<List<SshChannelDataMessage>> _waitForChannelDataWrites(
  _PacketForwardTransport transport, {
  required int count,
}) async {
  final DateTime deadline = DateTime.now().add(const Duration(seconds: 2));
  while (DateTime.now().isBefore(deadline)) {
    final List<SshChannelDataMessage> messages = transport.channelDataMessages;
    if (messages.length >= count) {
      return messages.sublist(0, count);
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  return transport.channelDataMessages;
}

class _PacketForwardTransport
    implements SshPacketTransport, SshGlobalRequestReplyTransport {
  _PacketForwardTransport({required List<SshGlobalRequestReply> replies})
      : _replies = List<SshGlobalRequestReply>.from(replies);

  final List<SshGlobalRequestReply> _replies;
  final StreamController<SshBinaryPacket> _incomingController =
      StreamController<SshBinaryPacket>();
  StreamIterator<SshBinaryPacket>? _incomingIterator;
  final List<List<int>> writtenPayloads = <List<int>>[];

  List<SshChannelDataMessage> get channelDataMessages => writtenPayloads
      .where((List<int> payload) => payload.isNotEmpty && payload.first == 94)
      .map(SshChannelDataMessage.decodePayload)
      .toList();

  void enqueuePacket(List<int> payload) {
    _incomingController.add(
      SshBinaryPacket(payload: payload, padding: const <int>[0, 0, 0, 0]),
    );
  }

  Future<void> close() async {
    final StreamIterator<SshBinaryPacket>? iterator = _incomingIterator;
    if (iterator != null) {
      await iterator.cancel();
    }
    await _incomingController.close();
  }

  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    return const SshHandshakeInfo(
      localIdentification: 'SSH-2.0-test-client',
      remoteIdentification: 'SSH-2.0-test-server',
    );
  }

  @override
  Future<void> disconnect() async {
    await close();
  }

  @override
  Future<SshBinaryPacket> readPacket() async {
    _incomingIterator ??= StreamIterator<SshBinaryPacket>(
      _incomingController.stream,
    );
    final bool hasNext = await _incomingIterator!.moveNext();
    if (!hasNext) {
      throw StateError('No more SSH packets are available.');
    }
    return _incomingIterator!.current;
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}

  @override
  Future<SshGlobalRequestReply> sendGlobalRequestWithReply(
    SshGlobalRequest request,
  ) async {
    return _replies.removeAt(0);
  }

  @override
  Future<void> writeBytes(List<int> bytes) async {}

  @override
  Future<void> writePacket(List<int> payload) async {
    writtenPayloads.add(List<int>.from(payload));
  }
}
