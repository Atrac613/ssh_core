import 'dart:typed_data';

import '../channels/channel.dart';
import '../channels/protocol.dart';
import '../transport/global_request.dart';
import '../transport/message_codec.dart';

const String sshTcpIpForwardRequestName = 'tcpip-forward';
const String sshCancelTcpIpForwardRequestName = 'cancel-tcpip-forward';
const String sshDirectTcpIpChannelType = 'direct-tcpip';
const String sshForwardedTcpIpChannelType = 'forwarded-tcpip';

class SshTcpIpForwardRequest {
  const SshTcpIpForwardRequest({
    required this.bindHost,
    required this.bindPort,
  });

  factory SshTcpIpForwardRequest.decode(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SshTcpIpForwardRequest request = SshTcpIpForwardRequest(
      bindHost: reader.readString(),
      bindPort: reader.readUint32(),
    );
    reader.expectDone();
    return request;
  }

  final String bindHost;
  final int bindPort;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(bindHost)
      ..writeUint32(bindPort);
    return writer.toBytes();
  }

  SshGlobalRequestMessage toGlobalRequest({bool wantReply = true}) {
    return SshGlobalRequestMessage(
      requestName: sshTcpIpForwardRequestName,
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshCancelTcpIpForwardRequest {
  const SshCancelTcpIpForwardRequest({
    required this.bindHost,
    required this.bindPort,
  });

  factory SshCancelTcpIpForwardRequest.decode(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SshCancelTcpIpForwardRequest request = SshCancelTcpIpForwardRequest(
      bindHost: reader.readString(),
      bindPort: reader.readUint32(),
    );
    reader.expectDone();
    return request;
  }

  final String bindHost;
  final int bindPort;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(bindHost)
      ..writeUint32(bindPort);
    return writer.toBytes();
  }

  SshGlobalRequestMessage toGlobalRequest({bool wantReply = true}) {
    return SshGlobalRequestMessage(
      requestName: sshCancelTcpIpForwardRequestName,
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshTcpIpForwardSuccessResponse {
  const SshTcpIpForwardSuccessResponse({this.boundPort});

  factory SshTcpIpForwardSuccessResponse.decode(List<int> payload) {
    if (payload.isEmpty) {
      return const SshTcpIpForwardSuccessResponse();
    }

    final SshPayloadReader reader = SshPayloadReader(payload);
    final SshTcpIpForwardSuccessResponse response =
        SshTcpIpForwardSuccessResponse(boundPort: reader.readUint32());
    reader.expectDone();
    return response;
  }

  factory SshTcpIpForwardSuccessResponse.fromSuccessMessage(
    SshRequestSuccessMessage message,
  ) {
    return SshTcpIpForwardSuccessResponse.decode(message.responseData);
  }

  final int? boundPort;

  Uint8List encode() {
    if (boundPort == null) {
      return Uint8List(0);
    }

    final SshPayloadWriter writer = SshPayloadWriter()..writeUint32(boundPort!);
    return writer.toBytes();
  }

  SshRequestSuccessMessage toSuccessMessage() {
    return SshRequestSuccessMessage(responseData: encode());
  }
}

class SshDirectTcpIpChannelOpenData {
  const SshDirectTcpIpChannelOpenData({
    required this.targetHost,
    required this.targetPort,
    required this.originatorHost,
    required this.originatorPort,
  });

  factory SshDirectTcpIpChannelOpenData.decode(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SshDirectTcpIpChannelOpenData data = SshDirectTcpIpChannelOpenData(
      targetHost: reader.readString(),
      targetPort: reader.readUint32(),
      originatorHost: reader.readString(),
      originatorPort: reader.readUint32(),
    );
    reader.expectDone();
    return data;
  }

  factory SshDirectTcpIpChannelOpenData.fromChannelOpenMessage(
    SshChannelOpenMessage message,
  ) {
    if (message.channelType != sshDirectTcpIpChannelType) {
      throw FormatException(
        'Expected $sshDirectTcpIpChannelType channel, '
        'received ${message.channelType}.',
      );
    }
    return SshDirectTcpIpChannelOpenData.decode(message.channelData);
  }

  final String targetHost;
  final int targetPort;
  final String originatorHost;
  final int originatorPort;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(targetHost)
      ..writeUint32(targetPort)
      ..writeString(originatorHost)
      ..writeUint32(originatorPort);
    return writer.toBytes();
  }

  SshChannelOpenMessage toChannelOpenMessage({
    required int senderChannel,
    SshChannelWindow localWindow = const SshChannelWindow(),
  }) {
    return SshChannelOpenMessage(
      channelType: sshDirectTcpIpChannelType,
      senderChannel: senderChannel,
      initialWindowSize: localWindow.initialSize,
      maximumPacketSize: localWindow.maxPacketSize,
      channelData: encode(),
    );
  }
}

class SshForwardedTcpIpChannelOpenData {
  const SshForwardedTcpIpChannelOpenData({
    required this.connectedHost,
    required this.connectedPort,
    required this.originatorHost,
    required this.originatorPort,
  });

  factory SshForwardedTcpIpChannelOpenData.decode(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final SshForwardedTcpIpChannelOpenData data =
        SshForwardedTcpIpChannelOpenData(
      connectedHost: reader.readString(),
      connectedPort: reader.readUint32(),
      originatorHost: reader.readString(),
      originatorPort: reader.readUint32(),
    );
    reader.expectDone();
    return data;
  }

  factory SshForwardedTcpIpChannelOpenData.fromChannelOpenMessage(
    SshChannelOpenMessage message,
  ) {
    if (message.channelType != sshForwardedTcpIpChannelType) {
      throw FormatException(
        'Expected $sshForwardedTcpIpChannelType channel, '
        'received ${message.channelType}.',
      );
    }
    return SshForwardedTcpIpChannelOpenData.decode(message.channelData);
  }

  final String connectedHost;
  final int connectedPort;
  final String originatorHost;
  final int originatorPort;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(connectedHost)
      ..writeUint32(connectedPort)
      ..writeString(originatorHost)
      ..writeUint32(originatorPort);
    return writer.toBytes();
  }

  SshChannelOpenMessage toChannelOpenMessage({
    required int senderChannel,
    SshChannelWindow localWindow = const SshChannelWindow(),
  }) {
    return SshChannelOpenMessage(
      channelType: sshForwardedTcpIpChannelType,
      senderChannel: senderChannel,
      initialWindowSize: localWindow.initialSize,
      maximumPacketSize: localWindow.maxPacketSize,
      channelData: encode(),
    );
  }
}
