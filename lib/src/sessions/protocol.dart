import 'dart:typed_data';

import '../channels/protocol.dart';
import '../pty/pty.dart';
import '../transport/message_codec.dart';

class SshPtyModesCodec {
  const SshPtyModesCodec();

  Uint8List encode(Map<SshPtyMode, int> modes) {
    final SshPayloadWriter writer = SshPayloadWriter();
    for (final MapEntry<SshPtyMode, int> entry in modes.entries) {
      writer
        ..writeByte(entry.key.opcode)
        ..writeUint32(entry.value);
    }
    writer.writeByte(0);
    return writer.toBytes();
  }

  Map<SshPtyMode, int> decode(List<int> bytes) {
    final SshPayloadReader reader = SshPayloadReader(bytes);
    final Map<SshPtyMode, int> result = <SshPtyMode, int>{};

    while (!reader.isDone) {
      final int opcode = reader.readByte();
      if (opcode == 0) {
        reader.expectDone();
        return result;
      }

      result[_modeFromOpcode(opcode)] = reader.readUint32();
    }

    throw const FormatException('SSH PTY modes were missing the terminator.');
  }

  SshPtyMode _modeFromOpcode(int opcode) {
    for (final SshPtyMode mode in const <SshPtyMode>[
      SshPtyMode.echo,
      SshPtyMode.canonical,
      SshPtyMode.signals,
      SshPtyMode.outputProcessing,
    ]) {
      if (mode.opcode == opcode) {
        return mode;
      }
    }

    throw FormatException('Unknown SSH PTY mode opcode: $opcode.');
  }
}

class SshEnvChannelRequest {
  const SshEnvChannelRequest({required this.name, required this.value});

  factory SshEnvChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshEnvChannelRequest request = SshEnvChannelRequest(
      name: reader.readString(),
      value: reader.readString(),
    );
    reader.expectDone();
    return request;
  }

  final String name;
  final String value;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(name)
      ..writeString(value);
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'env',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshPtyChannelRequest {
  SshPtyChannelRequest({
    required this.pty,
    this.modesCodec = const SshPtyModesCodec(),
  });

  factory SshPtyChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshPtyModesCodec modesCodec = const SshPtyModesCodec();
    final SshPtyConfig pty = SshPtyConfig(
      terminalType: reader.readString(),
      columns: reader.readUint32(),
      rows: reader.readUint32(),
      pixelWidth: reader.readUint32(),
      pixelHeight: reader.readUint32(),
      modes: modesCodec.decode(reader.readStringBytes()),
    );
    reader.expectDone();
    return SshPtyChannelRequest(pty: pty, modesCodec: modesCodec);
  }

  final SshPtyConfig pty;
  final SshPtyModesCodec modesCodec;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(pty.terminalType)
      ..writeUint32(pty.columns)
      ..writeUint32(pty.rows)
      ..writeUint32(pty.pixelWidth)
      ..writeUint32(pty.pixelHeight)
      ..writeStringBytes(modesCodec.encode(pty.modes));
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'pty-req',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshWindowChangeChannelRequest {
  const SshWindowChangeChannelRequest({
    required this.columns,
    required this.rows,
    this.pixelWidth = 0,
    this.pixelHeight = 0,
  });

  factory SshWindowChangeChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshWindowChangeChannelRequest request = SshWindowChangeChannelRequest(
      columns: reader.readUint32(),
      rows: reader.readUint32(),
      pixelWidth: reader.readUint32(),
      pixelHeight: reader.readUint32(),
    );
    reader.expectDone();
    return request;
  }

  final int columns;
  final int rows;
  final int pixelWidth;
  final int pixelHeight;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeUint32(columns)
      ..writeUint32(rows)
      ..writeUint32(pixelWidth)
      ..writeUint32(pixelHeight);
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'window-change',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshShellChannelRequest {
  const SshShellChannelRequest();

  factory SshShellChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    reader.expectDone();
    return const SshShellChannelRequest();
  }

  Uint8List encode() => Uint8List(0);

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'shell',
      wantReply: wantReply,
    );
  }
}

class SshExecChannelRequest {
  const SshExecChannelRequest({required this.command});

  factory SshExecChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshExecChannelRequest request = SshExecChannelRequest(
      command: reader.readString(),
    );
    reader.expectDone();
    return request;
  }

  final String command;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeString(command);
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'exec',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshSubsystemChannelRequest {
  const SshSubsystemChannelRequest({required this.subsystem});

  factory SshSubsystemChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshSubsystemChannelRequest request = SshSubsystemChannelRequest(
      subsystem: reader.readString(),
    );
    reader.expectDone();
    return request;
  }

  final String subsystem;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeString(subsystem);
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'subsystem',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshExitStatusChannelRequest {
  const SshExitStatusChannelRequest({required this.exitStatus});

  factory SshExitStatusChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshExitStatusChannelRequest request = SshExitStatusChannelRequest(
      exitStatus: reader.readUint32(),
    );
    reader.expectDone();
    return request;
  }

  final int exitStatus;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()..writeUint32(exitStatus);
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'exit-status',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}

class SshExitSignalChannelRequest {
  const SshExitSignalChannelRequest({
    required this.signalName,
    this.coreDumped = false,
    this.errorMessage = '',
    this.languageTag = '',
  });

  factory SshExitSignalChannelRequest.decode(List<int> requestData) {
    final SshPayloadReader reader = SshPayloadReader(requestData);
    final SshExitSignalChannelRequest request = SshExitSignalChannelRequest(
      signalName: reader.readString(),
      coreDumped: reader.readBool(),
      errorMessage: reader.readString(),
      languageTag: reader.readString(),
    );
    reader.expectDone();
    return request;
  }

  final String signalName;
  final bool coreDumped;
  final String errorMessage;
  final String languageTag;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(signalName)
      ..writeBool(coreDumped)
      ..writeString(errorMessage)
      ..writeString(languageTag);
    return writer.toBytes();
  }

  SshChannelRequestMessage toChannelRequestMessage(
    int recipientChannel, {
    bool wantReply = false,
  }) {
    return SshChannelRequestMessage(
      recipientChannel: recipientChannel,
      requestType: 'exit-signal',
      wantReply: wantReply,
      requestData: encode(),
    );
  }
}
