import 'dart:typed_data';

import '../transport/message_codec.dart';

enum SshChannelOpenFailureReason {
  administrativelyProhibited(1),
  connectFailed(2),
  unknownChannelType(3),
  resourceShortage(4);

  const SshChannelOpenFailureReason(this.code);

  final int code;

  static SshChannelOpenFailureReason fromCode(int code) {
    return values.firstWhere(
      (SshChannelOpenFailureReason value) => value.code == code,
      orElse: () => throw FormatException(
        'Unknown SSH channel open failure reason code: $code.',
      ),
    );
  }
}

class SshChannelOpenMessage {
  SshChannelOpenMessage({
    required this.channelType,
    required this.senderChannel,
    required this.initialWindowSize,
    required this.maximumPacketSize,
    List<int> channelData = const <int>[],
  }) : channelData = Uint8List.fromList(channelData);

  factory SshChannelOpenMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelOpen.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_OPEN (${SshMessageId.channelOpen.value}), '
        'received $messageId.',
      );
    }

    final SshChannelOpenMessage message = SshChannelOpenMessage(
      channelType: reader.readString(),
      senderChannel: reader.readUint32(),
      initialWindowSize: reader.readUint32(),
      maximumPacketSize: reader.readUint32(),
      channelData: reader.readBytes(reader.remainingByteCount),
    );
    reader.expectDone();
    return message;
  }

  final String channelType;
  final int senderChannel;
  final int initialWindowSize;
  final int maximumPacketSize;
  final Uint8List channelData;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelOpen.value)
      ..writeString(channelType)
      ..writeUint32(senderChannel)
      ..writeUint32(initialWindowSize)
      ..writeUint32(maximumPacketSize)
      ..writeBytes(channelData);
    return writer.toBytes();
  }
}

class SshChannelOpenConfirmationMessage {
  SshChannelOpenConfirmationMessage({
    required this.recipientChannel,
    required this.senderChannel,
    required this.initialWindowSize,
    required this.maximumPacketSize,
    List<int> channelData = const <int>[],
  }) : channelData = Uint8List.fromList(channelData);

  factory SshChannelOpenConfirmationMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelOpenConfirmation.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_OPEN_CONFIRMATION '
        '(${SshMessageId.channelOpenConfirmation.value}), received $messageId.',
      );
    }

    final SshChannelOpenConfirmationMessage message =
        SshChannelOpenConfirmationMessage(
      recipientChannel: reader.readUint32(),
      senderChannel: reader.readUint32(),
      initialWindowSize: reader.readUint32(),
      maximumPacketSize: reader.readUint32(),
      channelData: reader.readBytes(reader.remainingByteCount),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;
  final int senderChannel;
  final int initialWindowSize;
  final int maximumPacketSize;
  final Uint8List channelData;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelOpenConfirmation.value)
      ..writeUint32(recipientChannel)
      ..writeUint32(senderChannel)
      ..writeUint32(initialWindowSize)
      ..writeUint32(maximumPacketSize)
      ..writeBytes(channelData);
    return writer.toBytes();
  }
}

class SshChannelOpenFailureMessage {
  const SshChannelOpenFailureMessage({
    required this.recipientChannel,
    required this.reason,
    required this.description,
    this.languageTag = '',
  });

  factory SshChannelOpenFailureMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelOpenFailure.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_OPEN_FAILURE '
        '(${SshMessageId.channelOpenFailure.value}), received $messageId.',
      );
    }

    final SshChannelOpenFailureMessage message = SshChannelOpenFailureMessage(
      recipientChannel: reader.readUint32(),
      reason: SshChannelOpenFailureReason.fromCode(reader.readUint32()),
      description: reader.readString(),
      languageTag: reader.readString(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;
  final SshChannelOpenFailureReason reason;
  final String description;
  final String languageTag;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelOpenFailure.value)
      ..writeUint32(recipientChannel)
      ..writeUint32(reason.code)
      ..writeString(description)
      ..writeString(languageTag);
    return writer.toBytes();
  }
}

class SshChannelWindowAdjustMessage {
  const SshChannelWindowAdjustMessage({
    required this.recipientChannel,
    required this.bytesToAdd,
  });

  factory SshChannelWindowAdjustMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelWindowAdjust.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_WINDOW_ADJUST '
        '(${SshMessageId.channelWindowAdjust.value}), received $messageId.',
      );
    }

    final SshChannelWindowAdjustMessage message = SshChannelWindowAdjustMessage(
      recipientChannel: reader.readUint32(),
      bytesToAdd: reader.readUint32(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;
  final int bytesToAdd;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelWindowAdjust.value)
      ..writeUint32(recipientChannel)
      ..writeUint32(bytesToAdd);
    return writer.toBytes();
  }
}

class SshChannelDataMessage {
  SshChannelDataMessage({
    required this.recipientChannel,
    required List<int> data,
  }) : data = Uint8List.fromList(data);

  factory SshChannelDataMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelData.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_DATA (${SshMessageId.channelData.value}), '
        'received $messageId.',
      );
    }

    final SshChannelDataMessage message = SshChannelDataMessage(
      recipientChannel: reader.readUint32(),
      data: reader.readStringBytes(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;
  final Uint8List data;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelData.value)
      ..writeUint32(recipientChannel)
      ..writeStringBytes(data);
    return writer.toBytes();
  }
}

class SshChannelExtendedDataMessage {
  SshChannelExtendedDataMessage({
    required this.recipientChannel,
    required this.dataTypeCode,
    required List<int> data,
  }) : data = Uint8List.fromList(data);

  factory SshChannelExtendedDataMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelExtendedData.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_EXTENDED_DATA '
        '(${SshMessageId.channelExtendedData.value}), received $messageId.',
      );
    }

    final SshChannelExtendedDataMessage message = SshChannelExtendedDataMessage(
      recipientChannel: reader.readUint32(),
      dataTypeCode: reader.readUint32(),
      data: reader.readStringBytes(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;
  final int dataTypeCode;
  final Uint8List data;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelExtendedData.value)
      ..writeUint32(recipientChannel)
      ..writeUint32(dataTypeCode)
      ..writeStringBytes(data);
    return writer.toBytes();
  }
}

class SshChannelRequestMessage {
  SshChannelRequestMessage({
    required this.recipientChannel,
    required this.requestType,
    this.wantReply = false,
    List<int> requestData = const <int>[],
  }) : requestData = Uint8List.fromList(requestData);

  factory SshChannelRequestMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelRequest.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_REQUEST '
        '(${SshMessageId.channelRequest.value}), received $messageId.',
      );
    }

    final SshChannelRequestMessage message = SshChannelRequestMessage(
      recipientChannel: reader.readUint32(),
      requestType: reader.readString(),
      wantReply: reader.readBool(),
      requestData: reader.readBytes(reader.remainingByteCount),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;
  final String requestType;
  final bool wantReply;
  final Uint8List requestData;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelRequest.value)
      ..writeUint32(recipientChannel)
      ..writeString(requestType)
      ..writeBool(wantReply)
      ..writeBytes(requestData);
    return writer.toBytes();
  }
}

class SshChannelSuccessMessage {
  const SshChannelSuccessMessage({required this.recipientChannel});

  factory SshChannelSuccessMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelSuccess.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_SUCCESS '
        '(${SshMessageId.channelSuccess.value}), received $messageId.',
      );
    }

    final SshChannelSuccessMessage message = SshChannelSuccessMessage(
      recipientChannel: reader.readUint32(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelSuccess.value)
      ..writeUint32(recipientChannel);
    return writer.toBytes();
  }
}

class SshChannelFailureMessage {
  const SshChannelFailureMessage({required this.recipientChannel});

  factory SshChannelFailureMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelFailure.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_FAILURE '
        '(${SshMessageId.channelFailure.value}), received $messageId.',
      );
    }

    final SshChannelFailureMessage message = SshChannelFailureMessage(
      recipientChannel: reader.readUint32(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelFailure.value)
      ..writeUint32(recipientChannel);
    return writer.toBytes();
  }
}

class SshChannelEofMessage {
  const SshChannelEofMessage({required this.recipientChannel});

  factory SshChannelEofMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelEof.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_EOF (${SshMessageId.channelEof.value}), '
        'received $messageId.',
      );
    }

    final SshChannelEofMessage message = SshChannelEofMessage(
      recipientChannel: reader.readUint32(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelEof.value)
      ..writeUint32(recipientChannel);
    return writer.toBytes();
  }
}

class SshChannelCloseMessage {
  const SshChannelCloseMessage({required this.recipientChannel});

  factory SshChannelCloseMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.channelClose.value) {
      throw FormatException(
        'Expected SSH_MSG_CHANNEL_CLOSE (${SshMessageId.channelClose.value}), '
        'received $messageId.',
      );
    }

    final SshChannelCloseMessage message = SshChannelCloseMessage(
      recipientChannel: reader.readUint32(),
    );
    reader.expectDone();
    return message;
  }

  final int recipientChannel;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.channelClose.value)
      ..writeUint32(recipientChannel);
    return writer.toBytes();
  }
}
