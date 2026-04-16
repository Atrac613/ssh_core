import 'dart:async';
import 'dart:collection';

import '../forwarding/protocol.dart';
import '../transport/transport.dart';
import 'channel.dart';
import 'protocol.dart';

class SshPacketChannelOpenException implements Exception {
  const SshPacketChannelOpenException({
    required this.reason,
    required this.description,
  });

  final SshChannelOpenFailureReason reason;
  final String description;

  @override
  String toString() {
    return 'SshPacketChannelOpenException('
        'reason: $reason, '
        'description: $description'
        ')';
  }
}

class SshPacketChannel implements SshChannel {
  SshPacketChannel._(this._factory, this._state);

  final SshPacketChannelFactory _factory;
  final _PacketChannelState _state;

  @override
  int get id => _state.localChannelId;

  @override
  SshChannelType get type => _state.type;

  Stream<List<int>> get stdout => _state.stdoutController.stream;

  Stream<List<int>> get stderr => _state.stderrController.stream;

  Stream<SshChannelRequestMessage> get inboundRequests =>
      _state.requestController.stream;

  Future<void> get done => _state.doneCompleter.future;

  Future<void> sendData(List<int> data) async {
    await _factory._transport.writePacket(
      SshChannelDataMessage(
        recipientChannel: _state.remoteChannelId!,
        data: data,
      ).encodePayload(),
    );
  }

  Future<void> sendEof() async {
    if (_state.remoteChannelId == null || _state.eofSent) {
      return;
    }

    _state.eofSent = true;
    await _factory._transport.writePacket(
      SshChannelEofMessage(recipientChannel: _state.remoteChannelId!)
          .encodePayload(),
    );
  }

  @override
  Future<void> sendRequest(SshChannelRequest request) async {
    final int? remoteChannelId = _state.remoteChannelId;
    if (remoteChannelId == null) {
      throw StateError('SSH channel has not been opened yet.');
    }

    final Object? encodedPayload = request.payload['encodedPayload'];
    final List<int> requestData;
    if (encodedPayload == null) {
      requestData = const <int>[];
    } else if (encodedPayload is List<int>) {
      requestData = encodedPayload;
    } else {
      throw ArgumentError.value(
        encodedPayload,
        'request.payload["encodedPayload"]',
        'SSH packet channels expect encodedPayload to be a byte list.',
      );
    }

    Completer<bool>? replyCompleter;
    if (request.wantReply) {
      replyCompleter = Completer<bool>();
      _state.pendingRequestReplies.add(replyCompleter);
    }

    await _factory._transport.writePacket(
      SshChannelRequestMessage(
        recipientChannel: remoteChannelId,
        requestType: request.type,
        wantReply: request.wantReply,
        requestData: requestData,
      ).encodePayload(),
    );

    final Completer<bool>? pendingReply = replyCompleter;
    if (pendingReply == null) {
      return;
    }

    final bool succeeded = await pendingReply.future;
    if (!succeeded) {
      throw StateError('SSH channel request ${request.type} failed.');
    }
  }

  @override
  Future<void> close() async {
    final int? remoteChannelId = _state.remoteChannelId;
    if (remoteChannelId != null && !_state.closeSent) {
      _state.closeSent = true;
      await _factory._transport.writePacket(
        SshChannelCloseMessage(recipientChannel: remoteChannelId)
            .encodePayload(),
      );
    }

    if (_state.remoteClosed) {
      _state.finish();
    }
  }
}

class SshPacketChannelFactory implements SshChannelFactory {
  SshPacketChannelFactory({required SshPacketTransport transport})
      : _transport = transport;

  final SshPacketTransport _transport;
  final Map<int, _PacketChannelState> _channels = <int, _PacketChannelState>{};
  int _nextLocalChannelId = 0;
  bool _readLoopStarted = false;

  Future<SshPacketChannel> openSessionChannel({
    SshChannelWindow localWindow = const SshChannelWindow(),
  }) async {
    return (await openChannel(
      SshChannelOpenRequest.session(localWindow: localWindow),
    )) as SshPacketChannel;
  }

  @override
  Future<SshChannel> openChannel(SshChannelOpenRequest request) async {
    _ensureReadLoop();

    final int localChannelId = _nextLocalChannelId++;
    final _EncodedChannelOpen encodedRequest = _encodeOpenRequest(request);
    final _PacketChannelState state = _PacketChannelState(
      localChannelId: localChannelId,
      type: request.type,
    );
    final SshPacketChannel channel = SshPacketChannel._(this, state);
    state.channel = channel;
    _channels[localChannelId] = state;

    await _transport.writePacket(
      SshChannelOpenMessage(
        channelType: encodedRequest.channelType,
        senderChannel: localChannelId,
        initialWindowSize: request.localWindow.initialSize,
        maximumPacketSize: request.localWindow.maxPacketSize,
        channelData: encodedRequest.channelData,
      ).encodePayload(),
    );

    return state.openCompleter.future;
  }

  void _ensureReadLoop() {
    if (_readLoopStarted) {
      return;
    }

    _readLoopStarted = true;
    unawaited(_runReadLoop());
  }

  Future<void> _runReadLoop() async {
    try {
      for (;;) {
        final SshBinaryPacket packet = await _transport.readPacket();
        await _handlePacket(packet);
      }
    } catch (error, stackTrace) {
      for (final _PacketChannelState state in _channels.values) {
        if (!state.openCompleter.isCompleted) {
          state.openCompleter.completeError(error, stackTrace);
        }
        state.finish(error: error, stackTrace: stackTrace);
      }
      _channels.clear();
    }
  }

  Future<void> _handlePacket(SshBinaryPacket packet) async {
    switch (packet.messageId) {
      case 91:
        final SshChannelOpenConfirmationMessage confirmation =
            SshChannelOpenConfirmationMessage.decodePayload(packet.payload);
        final _PacketChannelState? state =
            _channels[confirmation.recipientChannel];
        if (state == null) {
          return;
        }
        state.remoteChannelId = confirmation.senderChannel;
        if (!state.openCompleter.isCompleted) {
          state.openCompleter.complete(state.channel);
        }
        return;
      case 92:
        final SshChannelOpenFailureMessage failure =
            SshChannelOpenFailureMessage.decodePayload(packet.payload);
        final _PacketChannelState? state = _channels.remove(
          failure.recipientChannel,
        );
        if (state == null) {
          return;
        }
        final SshPacketChannelOpenException error =
            SshPacketChannelOpenException(
          reason: failure.reason,
          description: failure.description,
        );
        if (!state.openCompleter.isCompleted) {
          state.openCompleter.completeError(error);
        }
        state.finish(error: error);
        return;
      case 93:
        SshChannelWindowAdjustMessage.decodePayload(packet.payload);
        return;
      case 94:
        final SshChannelDataMessage message =
            SshChannelDataMessage.decodePayload(packet.payload);
        _channels[message.recipientChannel]?.stdoutController.add(message.data);
        return;
      case 95:
        final SshChannelExtendedDataMessage message =
            SshChannelExtendedDataMessage.decodePayload(packet.payload);
        _channels[message.recipientChannel]?.stderrController.add(message.data);
        return;
      case 96:
        final SshChannelEofMessage message = SshChannelEofMessage.decodePayload(
          packet.payload,
        );
        final _PacketChannelState? state = _channels[message.recipientChannel];
        if (state == null) {
          return;
        }
        await state.closeOutputControllers();
        return;
      case 97:
        final SshChannelCloseMessage message =
            SshChannelCloseMessage.decodePayload(packet.payload);
        final _PacketChannelState? state = _channels.remove(
          message.recipientChannel,
        );
        if (state == null) {
          return;
        }
        state.remoteClosed = true;
        if (state.remoteChannelId != null && !state.closeSent) {
          state.closeSent = true;
          await _transport.writePacket(
            SshChannelCloseMessage(recipientChannel: state.remoteChannelId!)
                .encodePayload(),
          );
        }
        state.finish();
        return;
      case 98:
        final SshChannelRequestMessage message =
            SshChannelRequestMessage.decodePayload(packet.payload);
        _channels[message.recipientChannel]?.requestController.add(message);
        return;
      case 99:
        final SshChannelSuccessMessage message =
            SshChannelSuccessMessage.decodePayload(packet.payload);
        _channels[message.recipientChannel]?.completeNextRequestReply(true);
        return;
      case 100:
        final SshChannelFailureMessage message =
            SshChannelFailureMessage.decodePayload(packet.payload);
        _channels[message.recipientChannel]?.completeNextRequestReply(false);
        return;
      default:
        return;
    }
  }

  _EncodedChannelOpen _encodeOpenRequest(SshChannelOpenRequest request) {
    switch (request.type) {
      case SshChannelType.session:
        return const _EncodedChannelOpen(channelType: 'session');
      case SshChannelType.directTcpip:
        return _EncodedChannelOpen(
          channelType: sshDirectTcpIpChannelType,
          channelData: SshDirectTcpIpChannelOpenData(
            targetHost: _requireString(request.payload, 'targetHost'),
            targetPort: _requireInt(request.payload, 'targetPort'),
            originatorHost: _requireString(request.payload, 'originatorHost'),
            originatorPort: _requireInt(request.payload, 'originatorPort'),
          ).encode(),
        );
      case SshChannelType.forwardedTcpip:
        return _EncodedChannelOpen(
          channelType: sshForwardedTcpIpChannelType,
          channelData: SshForwardedTcpIpChannelOpenData(
            connectedHost: _requireString(request.payload, 'connectedHost'),
            connectedPort: _requireInt(request.payload, 'connectedPort'),
            originatorHost: _requireString(request.payload, 'originatorHost'),
            originatorPort: _requireInt(request.payload, 'originatorPort'),
          ).encode(),
        );
      case SshChannelType.x11:
      case SshChannelType.custom:
        final String channelType = request.subtype ??
            (throw StateError(
              'Custom SSH channel requests require a subtype string.',
            ));
        final Object? rawChannelData = request.payload['channelData'];
        if (rawChannelData == null) {
          return _EncodedChannelOpen(channelType: channelType);
        }
        if (rawChannelData is! List<int>) {
          throw ArgumentError.value(
            rawChannelData,
            'request.payload["channelData"]',
            'SSH channelData must be a byte list.',
          );
        }
        return _EncodedChannelOpen(
          channelType: channelType,
          channelData: rawChannelData,
        );
    }
  }

  String _requireString(Map<String, Object?> payload, String key) {
    final Object? value = payload[key];
    if (value is String) {
      return value;
    }
    throw ArgumentError.value(
      value,
      'payload[$key]',
      'Expected a String for SSH channel request payload.',
    );
  }

  int _requireInt(Map<String, Object?> payload, String key) {
    final Object? value = payload[key];
    if (value is int) {
      return value;
    }
    throw ArgumentError.value(
      value,
      'payload[$key]',
      'Expected an int for SSH channel request payload.',
    );
  }
}

class _PacketChannelState {
  _PacketChannelState({
    required this.localChannelId,
    required this.type,
  });

  final int localChannelId;
  final SshChannelType type;
  late final SshPacketChannel channel;
  final Completer<SshPacketChannel> openCompleter =
      Completer<SshPacketChannel>();
  final Completer<void> doneCompleter = Completer<void>();
  final StreamController<List<int>> stdoutController =
      StreamController<List<int>>();
  final StreamController<List<int>> stderrController =
      StreamController<List<int>>();
  final StreamController<SshChannelRequestMessage> requestController =
      StreamController<SshChannelRequestMessage>();
  final Queue<Completer<bool>> pendingRequestReplies = Queue<Completer<bool>>();

  int? remoteChannelId;
  bool closeSent = false;
  bool eofSent = false;
  bool remoteClosed = false;
  bool _finished = false;

  void completeNextRequestReply(bool value) {
    if (pendingRequestReplies.isEmpty) {
      return;
    }

    pendingRequestReplies.removeFirst().complete(value);
  }

  Future<void> closeOutputControllers() async {
    await stdoutController.close();
    await stderrController.close();
  }

  void finish({Object? error, StackTrace? stackTrace}) {
    if (_finished) {
      return;
    }

    _finished = true;
    unawaited(stdoutController.close());
    unawaited(stderrController.close());
    unawaited(requestController.close());
    while (pendingRequestReplies.isNotEmpty) {
      final Completer<bool> completer = pendingRequestReplies.removeFirst();
      if (!completer.isCompleted) {
        completer.complete(false);
      }
    }
    if (error != null) {
      if (!doneCompleter.isCompleted) {
        doneCompleter.completeError(error, stackTrace);
      }
      return;
    }
    if (!doneCompleter.isCompleted) {
      doneCompleter.complete();
    }
  }
}

class _EncodedChannelOpen {
  const _EncodedChannelOpen({
    required this.channelType,
    this.channelData = const <int>[],
  });

  final String channelType;
  final List<int> channelData;
}
