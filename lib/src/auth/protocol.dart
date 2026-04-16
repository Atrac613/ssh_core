import 'dart:typed_data';

import '../transport/message_codec.dart';
import 'auth.dart';

const String sshUserauthService = 'ssh-userauth';
const String sshConnectionService = 'ssh-connection';

class SshServiceRequestMessage {
  const SshServiceRequestMessage({required this.serviceName});

  factory SshServiceRequestMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.serviceRequest.value) {
      throw FormatException(
        'Expected SSH_MSG_SERVICE_REQUEST '
        '(${SshMessageId.serviceRequest.value}), received $messageId.',
      );
    }

    final SshServiceRequestMessage message = SshServiceRequestMessage(
      serviceName: reader.readString(),
    );
    reader.expectDone();
    return message;
  }

  final String serviceName;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.serviceRequest.value)
      ..writeString(serviceName);
    return writer.toBytes();
  }
}

class SshServiceAcceptMessage {
  const SshServiceAcceptMessage({required this.serviceName});

  factory SshServiceAcceptMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.serviceAccept.value) {
      throw FormatException(
        'Expected SSH_MSG_SERVICE_ACCEPT '
        '(${SshMessageId.serviceAccept.value}), received $messageId.',
      );
    }

    final SshServiceAcceptMessage message = SshServiceAcceptMessage(
      serviceName: reader.readString(),
    );
    reader.expectDone();
    return message;
  }

  final String serviceName;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.serviceAccept.value)
      ..writeString(serviceName);
    return writer.toBytes();
  }
}

class SshUserAuthRequestMessage {
  SshUserAuthRequestMessage({
    required this.username,
    this.serviceName = sshConnectionService,
    required this.methodName,
    List<int> methodPayload = const <int>[],
  }) : methodPayload = Uint8List.fromList(methodPayload);

  factory SshUserAuthRequestMessage.none({
    required String username,
    String serviceName = sshConnectionService,
  }) {
    return SshUserAuthRequestMessage(
      username: username,
      serviceName: serviceName,
      methodName: 'none',
    );
  }

  factory SshUserAuthRequestMessage.password({
    required String username,
    String serviceName = sshConnectionService,
    required String password,
    String? nextPassword,
  }) {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeBool(nextPassword != null)
      ..writeString(password);
    final String? replacementPassword = nextPassword;
    if (replacementPassword != null) {
      writer.writeString(replacementPassword);
    }

    return SshUserAuthRequestMessage(
      username: username,
      serviceName: serviceName,
      methodName: 'password',
      methodPayload: writer.toBytes(),
    );
  }

  factory SshUserAuthRequestMessage.publicKey({
    required String username,
    String serviceName = sshConnectionService,
    required String algorithm,
    required List<int> publicKey,
    List<int>? signature,
  }) {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeBool(signature != null)
      ..writeString(algorithm)
      ..writeStringBytes(publicKey);
    final List<int>? signatureBlob = signature;
    if (signatureBlob != null) {
      writer.writeStringBytes(signatureBlob);
    }

    return SshUserAuthRequestMessage(
      username: username,
      serviceName: serviceName,
      methodName: 'publickey',
      methodPayload: writer.toBytes(),
    );
  }

  factory SshUserAuthRequestMessage.keyboardInteractive({
    required String username,
    String serviceName = sshConnectionService,
    String languageTag = '',
    String submethods = '',
  }) {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(languageTag)
      ..writeString(submethods);
    return SshUserAuthRequestMessage(
      username: username,
      serviceName: serviceName,
      methodName: 'keyboard-interactive',
      methodPayload: writer.toBytes(),
    );
  }

  factory SshUserAuthRequestMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthRequest.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_REQUEST '
        '(${SshMessageId.userauthRequest.value}), received $messageId.',
      );
    }

    final SshUserAuthRequestMessage message = SshUserAuthRequestMessage(
      username: reader.readString(),
      serviceName: reader.readString(),
      methodName: reader.readString(),
      methodPayload: reader.readBytes(reader.remainingByteCount),
    );
    reader.expectDone();
    return message;
  }

  final String username;
  final String serviceName;
  final String methodName;
  final Uint8List methodPayload;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthRequest.value)
      ..writeString(username)
      ..writeString(serviceName)
      ..writeString(methodName)
      ..writeBytes(methodPayload);
    return writer.toBytes();
  }
}

class SshUserAuthFailureMessage {
  SshUserAuthFailureMessage({
    List<String> allowedMethods = const <String>[],
    this.partialSuccess = false,
  }) : allowedMethods = List.unmodifiable(allowedMethods);

  factory SshUserAuthFailureMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthFailure.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_FAILURE '
        '(${SshMessageId.userauthFailure.value}), received $messageId.',
      );
    }

    final SshUserAuthFailureMessage message = SshUserAuthFailureMessage(
      allowedMethods: reader.readNameList(),
      partialSuccess: reader.readBool(),
    );
    reader.expectDone();
    return message;
  }

  final List<String> allowedMethods;
  final bool partialSuccess;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthFailure.value)
      ..writeNameList(allowedMethods)
      ..writeBool(partialSuccess);
    return writer.toBytes();
  }
}

class SshUserAuthSuccessMessage {
  const SshUserAuthSuccessMessage();

  factory SshUserAuthSuccessMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthSuccess.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_SUCCESS '
        '(${SshMessageId.userauthSuccess.value}), received $messageId.',
      );
    }

    reader.expectDone();
    return const SshUserAuthSuccessMessage();
  }

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthSuccess.value);
    return writer.toBytes();
  }
}

class SshUserAuthBannerMessage {
  const SshUserAuthBannerMessage({
    required this.message,
    this.languageTag = '',
  });

  factory SshUserAuthBannerMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthBanner.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_BANNER '
        '(${SshMessageId.userauthBanner.value}), received $messageId.',
      );
    }

    final SshUserAuthBannerMessage message = SshUserAuthBannerMessage(
      message: reader.readString(),
      languageTag: reader.readString(),
    );
    reader.expectDone();
    return message;
  }

  final String message;
  final String languageTag;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthBanner.value)
      ..writeString(message)
      ..writeString(languageTag);
    return writer.toBytes();
  }
}

class SshUserAuthPkOkMessage {
  SshUserAuthPkOkMessage({
    required this.algorithm,
    required List<int> publicKey,
  }) : publicKey = Uint8List.fromList(publicKey);

  factory SshUserAuthPkOkMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthPkOk.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_PK_OK '
        '(${SshMessageId.userauthPkOk.value}), received $messageId.',
      );
    }

    final SshUserAuthPkOkMessage message = SshUserAuthPkOkMessage(
      algorithm: reader.readString(),
      publicKey: reader.readStringBytes(),
    );
    reader.expectDone();
    return message;
  }

  final String algorithm;
  final Uint8List publicKey;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthPkOk.value)
      ..writeString(algorithm)
      ..writeStringBytes(publicKey);
    return writer.toBytes();
  }
}

class SshUserAuthInfoRequestMessage {
  SshUserAuthInfoRequestMessage({
    this.name = '',
    this.instruction = '',
    this.languageTag = '',
    List<SshKeyboardInteractivePrompt> prompts =
        const <SshKeyboardInteractivePrompt>[],
  }) : prompts = List.unmodifiable(prompts);

  factory SshUserAuthInfoRequestMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthInfoRequest.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_INFO_REQUEST '
        '(${SshMessageId.userauthInfoRequest.value}), received $messageId.',
      );
    }

    final String name = reader.readString();
    final String instruction = reader.readString();
    final String languageTag = reader.readString();
    final int promptCount = reader.readUint32();
    final List<SshKeyboardInteractivePrompt> prompts =
        <SshKeyboardInteractivePrompt>[];
    for (int index = 0; index < promptCount; index += 1) {
      prompts.add(
        SshKeyboardInteractivePrompt(
          prompt: reader.readString(),
          echo: reader.readBool(),
        ),
      );
    }

    reader.expectDone();
    return SshUserAuthInfoRequestMessage(
      name: name,
      instruction: instruction,
      languageTag: languageTag,
      prompts: prompts,
    );
  }

  final String name;
  final String instruction;
  final String languageTag;
  final List<SshKeyboardInteractivePrompt> prompts;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthInfoRequest.value)
      ..writeString(name)
      ..writeString(instruction)
      ..writeString(languageTag)
      ..writeUint32(prompts.length);

    for (final SshKeyboardInteractivePrompt prompt in prompts) {
      writer
        ..writeString(prompt.prompt)
        ..writeBool(prompt.echo);
    }

    return writer.toBytes();
  }
}

class SshUserAuthInfoResponseMessage {
  SshUserAuthInfoResponseMessage({
    List<String> responses = const <String>[],
  }) : responses = List.unmodifiable(responses);

  factory SshUserAuthInfoResponseMessage.decodePayload(List<int> payload) {
    final SshPayloadReader reader = SshPayloadReader(payload);
    final int messageId = reader.readByte();
    if (messageId != SshMessageId.userauthInfoResponse.value) {
      throw FormatException(
        'Expected SSH_MSG_USERAUTH_INFO_RESPONSE '
        '(${SshMessageId.userauthInfoResponse.value}), received $messageId.',
      );
    }

    final int responseCount = reader.readUint32();
    final List<String> responses = <String>[];
    for (int index = 0; index < responseCount; index += 1) {
      responses.add(reader.readString());
    }

    reader.expectDone();
    return SshUserAuthInfoResponseMessage(responses: responses);
  }

  final List<String> responses;

  Uint8List encodePayload() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeByte(SshMessageId.userauthInfoResponse.value)
      ..writeUint32(responses.length);
    for (final String response in responses) {
      writer.writeString(response);
    }
    return writer.toBytes();
  }
}
