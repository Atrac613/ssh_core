import 'dart:typed_data';

import 'message_codec.dart';

class SshGlobalRequestMessage {
  SshGlobalRequestMessage({
    required this.requestName,
    this.wantReply = false,
    List<int> requestData = const <int>[],
  }) : requestData = Uint8List.fromList(requestData);

  factory SshGlobalRequestMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.globalRequest.value) {
      throw FormatException(
        'Expected SSH_MSG_GLOBAL_REQUEST '
        '(${SshMessageId.globalRequest.value}), received $messageId.',
      );
    }

    final SshGlobalRequestMessage message = SshGlobalRequestMessage(
      requestName: reader.readString(),
      wantReply: reader.readBool(),
      requestData: reader.readBytes(reader.remainingByteCount),
    );
    reader.expectDone();
    return message;
  }

  final String requestName;
  final bool wantReply;
  final Uint8List requestData;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.globalRequest.value)
      ..writeString(requestName)
      ..writeBool(wantReply)
      ..writeBytes(requestData);
    return writer.toBytes();
  }
}

class SshRequestSuccessMessage {
  SshRequestSuccessMessage({List<int> responseData = const <int>[]})
      : responseData = Uint8List.fromList(responseData);

  factory SshRequestSuccessMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.requestSuccess.value) {
      throw FormatException(
        'Expected SSH_MSG_REQUEST_SUCCESS '
        '(${SshMessageId.requestSuccess.value}), received $messageId.',
      );
    }

    final SshRequestSuccessMessage message = SshRequestSuccessMessage(
      responseData: reader.readBytes(reader.remainingByteCount),
    );
    reader.expectDone();
    return message;
  }

  final Uint8List responseData;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.requestSuccess.value)
      ..writeBytes(responseData);
    return writer.toBytes();
  }
}

class SshRequestFailureMessage {
  const SshRequestFailureMessage();

  factory SshRequestFailureMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.requestFailure.value) {
      throw FormatException(
        'Expected SSH_MSG_REQUEST_FAILURE '
        '(${SshMessageId.requestFailure.value}), received $messageId.',
      );
    }

    reader.expectDone();
    return const SshRequestFailureMessage();
  }

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.requestFailure.value);
    return writer.toBytes();
  }
}
