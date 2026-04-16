import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'crypto.dart';
import 'global_request.dart';
import 'key_exchange.dart';
import 'message_codec.dart';
import 'packet_protection.dart';
import 'transport.dart';

class SshSecureSocketTransport
    implements SshPacketTransport, SshGlobalRequestReplyTransport {
  SshSecureSocketTransport({
    this.bannerExchange = const SshBannerExchange(),
    this.tcpNoDelay = true,
    this.rekeyPolicy = const SshRekeyPolicy(),
    Random? random,
    List<String> keyExchangeAlgorithms =
        SshTransportAlgorithms.defaultKeyExchangeAlgorithms,
    List<String> serverHostKeyAlgorithms =
        SshTransportAlgorithms.defaultServerHostKeyAlgorithms,
    List<String> encryptionAlgorithms =
        SshTransportAlgorithms.defaultEncryptionAlgorithms,
    List<String> macAlgorithms = SshTransportAlgorithms.defaultMacAlgorithms,
    List<String> compressionAlgorithms =
        SshTransportAlgorithms.defaultCompressionAlgorithms,
  })  : _random = random ?? Random.secure(),
        keyExchangeAlgorithms = List.unmodifiable(keyExchangeAlgorithms),
        serverHostKeyAlgorithms = List.unmodifiable(serverHostKeyAlgorithms),
        encryptionAlgorithms = List.unmodifiable(encryptionAlgorithms),
        macAlgorithms = List.unmodifiable(macAlgorithms),
        compressionAlgorithms = List.unmodifiable(compressionAlgorithms);

  final SshBannerExchange bannerExchange;
  final bool tcpNoDelay;
  final SshRekeyPolicy rekeyPolicy;
  final Random _random;
  final List<String> keyExchangeAlgorithms;
  final List<String> serverHostKeyAlgorithms;
  final List<String> encryptionAlgorithms;
  final List<String> macAlgorithms;
  final List<String> compressionAlgorithms;

  Socket? _socket;
  StreamIterator<List<int>>? _incoming;
  final List<int> _incomingBuffer = <int>[];
  final Queue<SshBinaryPacket> _packetQueue = ListQueue<SshBinaryPacket>();
  final Queue<Completer<SshBinaryPacket>> _pendingPacketReaders =
      ListQueue<Completer<SshBinaryPacket>>();
  final Queue<Completer<SshGlobalRequestReply>> _pendingGlobalRequestReplies =
      ListQueue<Completer<SshGlobalRequestReply>>();
  SshPacketWriterState _writerState = SshPlainPacketWriterState();
  SshPacketReaderState _readerState = SshPlainPacketReaderState();
  _SshCompressionState _incomingCompression =
      const _SshIdentityCompressionState();
  _SshCompressionState _outgoingCompression =
      const _SshIdentityCompressionState();
  bool _hasAuthenticated = false;
  bool _delayedIncomingCompressionPending = false;
  bool _delayedOutgoingCompressionPending = false;
  SshHandshakeInfo? _handshake;
  SshTransportState _state = SshTransportState.disconnected;
  Future<void>? _readLoop;
  Completer<void>? _activeRekey;
  SshKexInitMessage? _pendingClientKexInit;
  int _sentPacketsSinceKeyExchange = 0;
  int _receivedPacketsSinceKeyExchange = 0;
  int _sentBytesSinceKeyExchange = 0;
  int _receivedBytesSinceKeyExchange = 0;
  DateTime? _lastKeyExchangeAt;
  Object? _terminalError;
  StackTrace? _terminalStackTrace;

  @override
  SshTransportState get state => _state;

  Socket? get socket => _socket;

  SshHandshakeInfo? get handshake => _handshake;

  Future<void> rekey() async {
    _ensureConnected();
    await _beginClientRekey(force: true);
  }

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    if (_state == SshTransportState.connecting ||
        _state == SshTransportState.connected) {
      throw StateError('SSH secure socket transport is already connected.');
    }

    _state = SshTransportState.connecting;
    Socket? socket;
    StreamIterator<List<int>>? incoming;

    try {
      socket = await Socket.connect(
        endpoint.host,
        endpoint.port,
        timeout: settings.connectTimeout,
      );

      if (tcpNoDelay) {
        socket.setOption(SocketOption.tcpNoDelay, true);
      }

      incoming = StreamIterator<List<int>>(socket);
      _socket = socket;
      _incoming = incoming;
      _incomingBuffer.clear();
      _packetQueue.clear();
      _pendingPacketReaders.clear();
      _pendingGlobalRequestReplies.clear();
      _writerState = SshPlainPacketWriterState();
      _readerState = SshPlainPacketReaderState();
      _incomingCompression = const _SshIdentityCompressionState();
      _outgoingCompression = const _SshIdentityCompressionState();
      _hasAuthenticated = false;
      _delayedIncomingCompressionPending = false;
      _delayedOutgoingCompressionPending = false;
      _activeRekey = null;
      _pendingClientKexInit = null;
      _terminalError = null;
      _terminalStackTrace = null;
      _readLoop = null;

      final SshBannerExchangeResult exchange = await _exchangeBanners(
        localIdentification: settings.clientIdentification,
      );
      final SshKexInitMessage clientKexInit = _buildClientKexInit();
      await _writePlainPacket(clientKexInit.encodePayload());

      final SshKexInitMessage serverKexInit = SshKexInitMessage.decodePayload(
        (await _readPacketWithState(SshPlainPacketReaderState())).payload,
      );

      final _SshKeyExchangeResult keyExchange = await _runKeyExchangeRound(
        localIdentification: exchange.localBanner.value,
        remoteIdentification: exchange.remoteBanner.value,
        clientKexInit: clientKexInit,
        serverKexInit: serverKexInit,
        sessionIdentifier: null,
        writePacket: _writePlainPacket,
        readPacket: () => _readPacketWithState(SshPlainPacketReaderState()),
      );

      _handshake = keyExchange.handshake;
      _resetRekeyCounters();
      _state = SshTransportState.connected;
      _startReadLoop();
      return keyExchange.handshake;
    } catch (_) {
      _handshake = null;
      _state = SshTransportState.disconnected;
      await _closeResources();
      rethrow;
    }
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {
    if (!request.wantReply) {
      await _writeApplicationPacket(
        SshGlobalRequestMessage(
          requestName: request.type,
          wantReply: false,
          requestData: _resolveGlobalRequestData(request),
        ).encodePayload(),
      );
      return;
    }

    await sendGlobalRequestWithReply(request);
  }

  @override
  Future<SshGlobalRequestReply> sendGlobalRequestWithReply(
    SshGlobalRequest request,
  ) async {
    _ensureConnected();
    final List<int> requestData = _resolveGlobalRequestData(request);

    if (!request.wantReply) {
      await _writeApplicationPacket(
        SshGlobalRequestMessage(
          requestName: request.type,
          wantReply: false,
          requestData: requestData,
        ).encodePayload(),
      );
      return SshGlobalRequestReply.success();
    }

    final Completer<SshGlobalRequestReply> replyCompleter =
        Completer<SshGlobalRequestReply>();
    _pendingGlobalRequestReplies.add(replyCompleter);
    try {
      await _writeApplicationPacket(
        SshGlobalRequestMessage(
          requestName: request.type,
          wantReply: true,
          requestData: requestData,
        ).encodePayload(),
      );
      return await replyCompleter.future;
    } catch (error, stackTrace) {
      _pendingGlobalRequestReplies.remove(replyCompleter);
      if (!replyCompleter.isCompleted) {
        replyCompleter.completeError(error, stackTrace);
      }
      rethrow;
    }
  }

  @override
  Future<void> disconnect() async {
    if (_state == SshTransportState.closed) {
      return;
    }

    _state = SshTransportState.closed;
    _handshake = null;
    await _closeResources();
    _failPending(StateError('SSH secure socket transport is closed.'));
  }

  @override
  Future<SshBinaryPacket> readPacket() async {
    _ensureConnected();
    _throwTerminalErrorIfNeeded();

    if (_packetQueue.isNotEmpty) {
      return _packetQueue.removeFirst();
    }

    final Completer<SshBinaryPacket> completer = Completer<SshBinaryPacket>();
    _pendingPacketReaders.add(completer);
    return completer.future;
  }

  @override
  Future<void> writeBytes(List<int> bytes) async {
    final Socket socket = _requireSocket();
    socket.add(bytes);
    await socket.flush();
  }

  @override
  Future<void> writePacket(List<int> payload) async {
    _ensureConnected();
    await _writeApplicationPacket(payload);
  }

  Future<SshBannerExchangeResult> _exchangeBanners({
    required String localIdentification,
  }) async {
    await writeBytes(
      utf8.encode(bannerExchange.formatLocalLine(localIdentification)),
    );

    final List<String> remoteLines = <String>[];
    for (;;) {
      final String? line = _tryReadLine();
      if (line != null) {
        remoteLines.add(line);
        if (line.startsWith('SSH-')) {
          return bannerExchange.resolve(
            localIdentification: localIdentification,
            remoteLines: remoteLines,
          );
        }
      } else if (!await _fillBuffer()) {
        throw StateError(
          'SSH peer closed before sending an identification line.',
        );
      }
    }
  }

  Future<_SshKeyExchangeResult> _runKeyExchangeRound({
    required String localIdentification,
    required String remoteIdentification,
    required SshKexInitMessage clientKexInit,
    required SshKexInitMessage serverKexInit,
    required List<int>? sessionIdentifier,
    required Future<void> Function(List<int> payload) writePacket,
    required Future<SshBinaryPacket> Function() readPacket,
  }) async {
    final SshNegotiatedAlgorithms negotiatedAlgorithms =
        const SshAlgorithmNegotiator().negotiate(
      clientProposal: clientKexInit,
      serverProposal: serverKexInit,
    );
    _validateNegotiatedAlgorithms(negotiatedAlgorithms);

    if (negotiatedAlgorithms.ignoreGuessedServerPacket) {
      await readPacket();
    }

    final SshCurve25519KeyPair keyPair = SshCurve25519KeyPair.generate(_random);
    await writePacket(
      SshKexEcdhInitMessage(
        clientEphemeralPublicKey: keyPair.publicKey,
      ).encodePayload(),
    );

    final SshKexEcdhReplyMessage reply = SshKexEcdhReplyMessage.decodePayload(
      (await readPacket()).payload,
    );
    final BigInt sharedSecret = keyPair.computeSharedSecret(
      reply.serverEphemeralPublicKey,
    );
    final Uint8List exchangeHash =
        const SshExchangeHashComputer().sha256FromInput(
      SshKexEcdhExchangeHashInput(
        clientIdentification: localIdentification,
        serverIdentification: remoteIdentification,
        clientKexInitPayload: clientKexInit.encodePayload(),
        serverKexInitPayload: serverKexInit.encodePayload(),
        hostKey: reply.hostKey,
        clientEphemeralPublicKey: keyPair.publicKey,
        serverEphemeralPublicKey: reply.serverEphemeralPublicKey,
        sharedSecret: sharedSecret,
      ),
    );

    final bool signatureVerified =
        const SshHostKeySignatureVerifier().verifyExchangeHash(
      hostKey: reply.hostKey,
      signature: reply.decodedExchangeHashSignature,
      exchangeHash: exchangeHash,
      negotiatedHostKeyAlgorithm: negotiatedAlgorithms.serverHostKey,
    );
    if (!signatureVerified) {
      throw const SshTransportCryptoException(
        'SSH exchange hash signature verification failed.',
      );
    }

    await writePacket(const SshNewKeysMessage().encodePayload());
    SshNewKeysMessage.decodePayload((await readPacket()).payload);

    final SshCipherAlgorithm clientCipher = _requireCipherAlgorithm(
      negotiatedAlgorithms.encryptionClientToServer,
    );
    final SshCipherAlgorithm serverCipher = _requireCipherAlgorithm(
      negotiatedAlgorithms.encryptionServerToClient,
    );
    final int clientIvLength = clientCipher.ivLength;
    final int serverIvLength = serverCipher.ivLength;
    final int clientKeyLength = clientCipher.keyLength;
    final int serverKeyLength = serverCipher.keyLength;
    final int clientMacKeyLength = clientCipher.macEmbedded
        ? 0
        : _requireMacAlgorithm(negotiatedAlgorithms.macClientToServer)
            .keyLength;
    final int serverMacKeyLength = serverCipher.macEmbedded
        ? 0
        : _requireMacAlgorithm(negotiatedAlgorithms.macServerToClient)
            .keyLength;
    final List<int> effectiveSessionIdentifier = Uint8List.fromList(
      sessionIdentifier ?? exchangeHash,
    );
    final SshDerivedKeys derivedKeys = const SshKeyDerivation().deriveSha256(
      context: SshKeyDerivationContext(
        sharedSecret: sharedSecret,
        exchangeHash: exchangeHash,
        sessionIdentifier: effectiveSessionIdentifier,
      ),
      ivLength: max(clientIvLength, serverIvLength),
      encryptionKeyLength: max(clientKeyLength, serverKeyLength),
      integrityKeyLength: max(clientMacKeyLength, serverMacKeyLength),
    );

    _writerState = sshCreatePacketWriterState(
      encryptionAlgorithm: negotiatedAlgorithms.encryptionClientToServer,
      encryptionKey: derivedKeys.encryptionKeyClientToServer.sublist(
        0,
        clientKeyLength,
      ),
      initialVector:
          derivedKeys.initialIvClientToServer.sublist(0, clientIvLength),
      macKey:
          derivedKeys.integrityKeyClientToServer.sublist(0, clientMacKeyLength),
      macAlgorithm: negotiatedAlgorithms.macClientToServer,
    );
    _readerState = sshCreatePacketReaderState(
      encryptionAlgorithm: negotiatedAlgorithms.encryptionServerToClient,
      encryptionKey: derivedKeys.encryptionKeyServerToClient.sublist(
        0,
        serverKeyLength,
      ),
      initialVector:
          derivedKeys.initialIvServerToClient.sublist(0, serverIvLength),
      macKey:
          derivedKeys.integrityKeyServerToClient.sublist(0, serverMacKeyLength),
      macAlgorithm: negotiatedAlgorithms.macServerToClient,
    );
    _configureCompression(negotiatedAlgorithms);

    final SshHandshakeInfo handshake = SshHandshakeInfo(
      localIdentification: localIdentification,
      remoteIdentification: remoteIdentification,
      negotiatedAlgorithms: negotiatedAlgorithms.asHandshakeMap(),
      sessionIdentifier: effectiveSessionIdentifier,
      hostKey: reply.hostKey,
    );
    return _SshKeyExchangeResult(
      handshake: handshake,
      negotiatedAlgorithms: negotiatedAlgorithms,
    );
  }

  Future<void> _writeApplicationPacket(List<int> payload) async {
    final Completer<void>? activeRekey = _activeRekey;
    if (activeRekey != null) {
      await activeRekey.future;
    }

    if (_shouldInitiateRekey()) {
      await _beginClientRekey(force: false);
    }

    final Completer<void>? triggeredRekey = _activeRekey;
    if (triggeredRekey != null) {
      await triggeredRekey.future;
    }

    await _writeCurrentPacket(payload, countTowardsRekey: true);
  }

  Future<void> _writeCurrentPacket(
    List<int> payload, {
    required bool countTowardsRekey,
  }) async {
    final Uint8List encodedPacket = _writerState.encode(
      _outgoingCompression.compress(payload),
    );
    await writeBytes(encodedPacket);
    if (countTowardsRekey) {
      _sentPacketsSinceKeyExchange += 1;
      _sentBytesSinceKeyExchange += encodedPacket.length;
    }
  }

  Future<void> _beginClientRekey({required bool force}) async {
    final Completer<void>? activeRekey = _activeRekey;
    if (activeRekey != null) {
      return activeRekey.future;
    }

    if (!force && !_shouldInitiateRekey()) {
      return;
    }

    final Completer<void> completer = Completer<void>();
    final SshKexInitMessage clientKexInit = _buildClientKexInit();
    _activeRekey = completer;
    _pendingClientKexInit = clientKexInit;

    try {
      await _writeCurrentPacket(
        clientKexInit.encodePayload(),
        countTowardsRekey: false,
      );
    } catch (error, stackTrace) {
      _pendingClientKexInit = null;
      _activeRekey = null;
      if (!completer.isCompleted) {
        completer.completeError(error, stackTrace);
      }
      rethrow;
    }

    await completer.future;
  }

  bool _shouldInitiateRekey() {
    final DateTime? lastKeyExchangeAt = _lastKeyExchangeAt;
    if (lastKeyExchangeAt == null) {
      return false;
    }

    return rekeyPolicy.shouldRekey(
      sentPackets: _sentPacketsSinceKeyExchange,
      receivedPackets: _receivedPacketsSinceKeyExchange,
      sentBytes: _sentBytesSinceKeyExchange,
      receivedBytes: _receivedBytesSinceKeyExchange,
      elapsed: DateTime.now().difference(lastKeyExchangeAt),
    );
  }

  void _resetRekeyCounters() {
    _sentPacketsSinceKeyExchange = 0;
    _receivedPacketsSinceKeyExchange = 0;
    _sentBytesSinceKeyExchange = 0;
    _receivedBytesSinceKeyExchange = 0;
    _lastKeyExchangeAt = DateTime.now();
  }

  void _startReadLoop() {
    if (_readLoop != null) {
      return;
    }

    _readLoop = _runReadLoop();
  }

  Future<void> _runReadLoop() async {
    try {
      for (;;) {
        final SshBinaryPacket packet =
            await _readApplicationPacketWithState(_readerState);
        final bool handledInternally = await _handleInternalPacket(packet);
        if (handledInternally) {
          continue;
        }

        _receivedPacketsSinceKeyExchange += 1;
        _receivedBytesSinceKeyExchange += packet.frameLength;
        if (packet.messageId == SshMessageId.userauthSuccess.value) {
          _hasAuthenticated = true;
          _activateDelayedCompressionIfNeeded();
        }
        _enqueuePacket(packet);

        if (_shouldInitiateRekey()) {
          unawaited(_beginClientRekey(force: false));
        }
      }
    } catch (error, stackTrace) {
      if (_state == SshTransportState.closed) {
        return;
      }
      _terminalError = error;
      _terminalStackTrace = stackTrace;
      _failPending(error, stackTrace);
    }
  }

  Future<SshBinaryPacket> _readApplicationPacketWithState(
    SshPacketReaderState readerState,
  ) async {
    final SshBinaryPacket packet = await _readPacketWithState(readerState);
    if (_incomingCompression is _SshIdentityCompressionState) {
      return packet;
    }

    return SshBinaryPacket(
      payload: _incomingCompression.decompress(packet.payload),
      padding: packet.padding,
    );
  }

  Future<bool> _handleInternalPacket(SshBinaryPacket packet) async {
    switch (packet.messageId) {
      case 20:
        await _handleRekey(
          SshKexInitMessage.decodePayload(packet.payload),
        );
        return true;
      case 81:
        return _completeGlobalRequestSuccess(packet.payload);
      case 82:
        return _completeGlobalRequestFailure(packet.payload);
      default:
        return false;
    }
  }

  Future<void> _handleRekey(SshKexInitMessage serverKexInit) async {
    final Completer<void> completer = _activeRekey ?? Completer<void>();
    _activeRekey ??= completer;

    try {
      SshKexInitMessage clientKexInit =
          _pendingClientKexInit ?? _buildClientKexInit();
      if (_pendingClientKexInit == null) {
        _pendingClientKexInit = clientKexInit;
        await _writeCurrentPacket(
          clientKexInit.encodePayload(),
          countTowardsRekey: false,
        );
      }

      final SshHandshakeInfo currentHandshake = _requireHandshake();
      final _SshKeyExchangeResult keyExchange = await _runKeyExchangeRound(
        localIdentification: currentHandshake.localIdentification,
        remoteIdentification: currentHandshake.remoteIdentification,
        clientKexInit: clientKexInit,
        serverKexInit: serverKexInit,
        sessionIdentifier: currentHandshake.sessionIdentifier,
        writePacket: (List<int> payload) => _writeCurrentPacket(
          payload,
          countTowardsRekey: false,
        ),
        readPacket: () => _readApplicationPacketWithState(_readerState),
      );

      _handshake = keyExchange.handshake;
      _resetRekeyCounters();
      if (!completer.isCompleted) {
        completer.complete();
      }
    } catch (error, stackTrace) {
      if (!completer.isCompleted) {
        completer.completeError(error, stackTrace);
      }
      rethrow;
    } finally {
      _pendingClientKexInit = null;
      if (identical(_activeRekey, completer)) {
        _activeRekey = null;
      }
    }
  }

  bool _completeGlobalRequestSuccess(List<int> payload) {
    if (_pendingGlobalRequestReplies.isEmpty) {
      return false;
    }

    final SshRequestSuccessMessage success =
        SshRequestSuccessMessage.decodePayload(payload);
    _pendingGlobalRequestReplies.removeFirst().complete(
          SshGlobalRequestReply.success(responseData: success.responseData),
        );
    return true;
  }

  bool _completeGlobalRequestFailure(List<int> payload) {
    if (_pendingGlobalRequestReplies.isEmpty) {
      return false;
    }

    SshRequestFailureMessage.decodePayload(payload);
    _pendingGlobalRequestReplies.removeFirst().complete(
          SshGlobalRequestReply.failure(),
        );
    return true;
  }

  void _enqueuePacket(SshBinaryPacket packet) {
    if (_pendingPacketReaders.isNotEmpty) {
      _pendingPacketReaders.removeFirst().complete(packet);
      return;
    }

    _packetQueue.addLast(packet);
  }

  SshKexInitMessage _buildClientKexInit() {
    return SshKexInitMessage(
      cookie: List<int>.generate(16, (_) => _random.nextInt(256)),
      kexAlgorithms: keyExchangeAlgorithms,
      serverHostKeyAlgorithms: serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer: encryptionAlgorithms,
      encryptionAlgorithmsServerToClient: encryptionAlgorithms,
      macAlgorithmsClientToServer: macAlgorithms,
      macAlgorithmsServerToClient: macAlgorithms,
      compressionAlgorithmsClientToServer: compressionAlgorithms,
      compressionAlgorithmsServerToClient: compressionAlgorithms,
    );
  }

  void _validateNegotiatedAlgorithms(SshNegotiatedAlgorithms negotiated) {
    _requireKeyExchangeAlgorithm(negotiated.keyExchange);
    _requireHostKeyAlgorithm(negotiated.serverHostKey);
    final SshCipherAlgorithm clientCipher = _requireCipherAlgorithm(
      negotiated.encryptionClientToServer,
    );
    final SshCipherAlgorithm serverCipher = _requireCipherAlgorithm(
      negotiated.encryptionServerToClient,
    );
    if (!clientCipher.macEmbedded) {
      _requireMacAlgorithm(negotiated.macClientToServer);
    }
    if (!serverCipher.macEmbedded) {
      _requireMacAlgorithm(negotiated.macServerToClient);
    }
    _validateCompressionAlgorithm(negotiated.compressionClientToServer);
    _validateCompressionAlgorithm(negotiated.compressionServerToClient);
  }

  void _configureCompression(SshNegotiatedAlgorithms negotiated) {
    _delayedOutgoingCompressionPending =
        negotiated.compressionClientToServer == sshZlibOpenSshCompression &&
            !_hasAuthenticated;
    _delayedIncomingCompressionPending =
        negotiated.compressionServerToClient == sshZlibOpenSshCompression &&
            !_hasAuthenticated;

    _outgoingCompression = _delayedOutgoingCompressionPending
        ? const _SshIdentityCompressionState()
        : _createCompressionState(
            _normalizeCompressionAlgorithm(
              negotiated.compressionClientToServer,
            ),
          );
    _incomingCompression = _delayedIncomingCompressionPending
        ? const _SshIdentityCompressionState()
        : _createCompressionState(
            _normalizeCompressionAlgorithm(
              negotiated.compressionServerToClient,
            ),
          );
  }

  void _activateDelayedCompressionIfNeeded() {
    if (_delayedOutgoingCompressionPending) {
      _outgoingCompression = _createCompressionState(sshZlibCompression);
      _delayedOutgoingCompressionPending = false;
    }
    if (_delayedIncomingCompressionPending) {
      _incomingCompression = _createCompressionState(sshZlibCompression);
      _delayedIncomingCompressionPending = false;
    }
  }

  void _validateCompressionAlgorithm(String algorithm) {
    _requireCompressionAlgorithm(algorithm);
  }

  String _normalizeCompressionAlgorithm(String algorithm) {
    return _requireCompressionAlgorithm(algorithm).normalizedName;
  }

  _SshCompressionState _createCompressionState(String algorithm) {
    switch (algorithm) {
      case sshNoCompression:
        return const _SshIdentityCompressionState();
      case sshZlibCompression:
        return _SshZLibCompressionState();
    }

    throw SshTransportCryptoException(
      'Unsupported SSH compression algorithm: $algorithm.',
    );
  }

  void _requireKeyExchangeAlgorithm(String algorithm) {
    try {
      SshTransportAlgorithms.keyExchangeAlgorithm(algorithm);
    } on ArgumentError {
      throw SshTransportCryptoException(
        'Unsupported SSH key exchange algorithm: $algorithm.',
      );
    }
  }

  void _requireHostKeyAlgorithm(String algorithm) {
    try {
      SshTransportAlgorithms.hostKeyAlgorithm(algorithm);
    } on ArgumentError {
      throw SshTransportCryptoException(
        'Unsupported SSH host key algorithm: $algorithm.',
      );
    }
  }

  SshCipherAlgorithm _requireCipherAlgorithm(String algorithm) {
    try {
      return SshTransportAlgorithms.cipherAlgorithm(algorithm);
    } on ArgumentError {
      throw SshTransportCryptoException(
        'Unsupported SSH encryption algorithm: $algorithm.',
      );
    }
  }

  SshMacAlgorithm _requireMacAlgorithm(String algorithm) {
    try {
      return SshTransportAlgorithms.macAlgorithm(algorithm);
    } on ArgumentError {
      throw SshTransportCryptoException(
        'Unsupported SSH MAC algorithm: $algorithm.',
      );
    }
  }

  SshCompressionAlgorithm _requireCompressionAlgorithm(String algorithm) {
    try {
      return SshTransportAlgorithms.compressionAlgorithm(algorithm);
    } on ArgumentError {
      throw SshTransportCryptoException(
        'Unsupported SSH compression algorithm: $algorithm.',
      );
    }
  }

  Future<void> _writePlainPacket(List<int> payload) async {
    final SshPlainPacketWriterState writer = SshPlainPacketWriterState();
    await writeBytes(writer.encode(payload));
  }

  Future<SshBinaryPacket> _readPacketWithState(
    SshPacketReaderState readerState,
  ) async {
    for (;;) {
      final int? expectedLength = readerState.expectedFrameLength(
        _incomingBuffer,
      );
      if (expectedLength != null && _incomingBuffer.length >= expectedLength) {
        final SshBinaryPacket? packet = readerState.tryRead(_incomingBuffer);
        if (packet == null) {
          throw StateError('SSH packet reader did not decode a packet.');
        }
        _incomingBuffer.removeRange(0, expectedLength);
        return packet;
      }

      if (!await _fillBuffer()) {
        throw StateError(
          'SSH peer closed before a complete packet was received.',
        );
      }
    }
  }

  String? _tryReadLine() {
    final int lineFeedIndex = _incomingBuffer.indexOf(10);
    if (lineFeedIndex < 0) {
      return null;
    }

    final int contentEnd =
        lineFeedIndex > 0 && _incomingBuffer[lineFeedIndex - 1] == 13
            ? lineFeedIndex - 1
            : lineFeedIndex;
    final List<int> lineBytes = _incomingBuffer.sublist(0, contentEnd);
    _incomingBuffer.removeRange(0, lineFeedIndex + 1);
    return utf8.decode(lineBytes);
  }

  Future<bool> _fillBuffer() async {
    final StreamIterator<List<int>> incoming = _requireIncoming();
    final bool hasNext = await incoming.moveNext();
    if (!hasNext) {
      return false;
    }
    _incomingBuffer.addAll(incoming.current);
    return true;
  }

  List<int> _resolveGlobalRequestData(SshGlobalRequest request) {
    final Object? encodedPayload = request.payload['encodedPayload'];
    if (encodedPayload == null) {
      return const <int>[];
    }
    if (encodedPayload is List<int>) {
      return encodedPayload;
    }

    throw ArgumentError.value(
      encodedPayload,
      'request.payload["encodedPayload"]',
      'SSH global request payload must be a byte list.',
    );
  }

  void _throwTerminalErrorIfNeeded() {
    final Object? terminalError = _terminalError;
    if (terminalError == null) {
      return;
    }

    Error.throwWithStackTrace(
      terminalError,
      _terminalStackTrace ?? StackTrace.current,
    );
  }

  void _ensureConnected() {
    if (_state != SshTransportState.connected) {
      throw StateError('SSH secure socket transport is not connected.');
    }
  }

  Socket _requireSocket() {
    final Socket? socket = _socket;
    if (socket == null) {
      throw StateError('SSH secure socket transport has no active socket.');
    }
    return socket;
  }

  StreamIterator<List<int>> _requireIncoming() {
    final StreamIterator<List<int>>? incoming = _incoming;
    if (incoming == null) {
      throw StateError('SSH secure socket transport has no active input.');
    }
    return incoming;
  }

  SshHandshakeInfo _requireHandshake() {
    final SshHandshakeInfo? handshake = _handshake;
    if (handshake == null) {
      throw StateError('SSH secure socket transport has no handshake state.');
    }
    return handshake;
  }

  void _failPending(Object error, [StackTrace? stackTrace]) {
    while (_pendingPacketReaders.isNotEmpty) {
      _pendingPacketReaders.removeFirst().completeError(error, stackTrace);
    }

    while (_pendingGlobalRequestReplies.isNotEmpty) {
      _pendingGlobalRequestReplies.removeFirst().completeError(
            error,
            stackTrace,
          );
    }

    final Completer<void>? activeRekey = _activeRekey;
    if (activeRekey != null && !activeRekey.isCompleted) {
      activeRekey.completeError(error, stackTrace);
    }
  }

  Future<void> _closeResources() async {
    final StreamIterator<List<int>>? incoming = _incoming;
    final Socket? socket = _socket;
    _incoming = null;
    _socket = null;
    _incomingBuffer.clear();

    if (incoming != null) {
      await incoming.cancel();
    }

    if (socket != null) {
      await socket.close();
      socket.destroy();
    }
  }
}

abstract class _SshCompressionState {
  Uint8List compress(List<int> payload);

  Uint8List decompress(List<int> payload);
}

class _SshIdentityCompressionState implements _SshCompressionState {
  const _SshIdentityCompressionState();

  @override
  Uint8List compress(List<int> payload) => Uint8List.fromList(payload);

  @override
  Uint8List decompress(List<int> payload) => Uint8List.fromList(payload);
}

class _SshZLibCompressionState implements _SshCompressionState {
  final RawZLibFilter _deflater = RawZLibFilter.deflateFilter();
  final RawZLibFilter _inflater = RawZLibFilter.inflateFilter();

  @override
  Uint8List compress(List<int> payload) {
    _deflater.process(payload, 0, payload.length);
    return _takeProcessedBytes(_deflater);
  }

  @override
  Uint8List decompress(List<int> payload) {
    _inflater.process(payload, 0, payload.length);
    return _takeProcessedBytes(_inflater);
  }

  Uint8List _takeProcessedBytes(RawZLibFilter filter) {
    final BytesBuilder bytes = BytesBuilder(copy: false);
    for (;;) {
      final List<int>? chunk = filter.processed(flush: true);
      if (chunk == null) {
        break;
      }
      bytes.add(chunk);
    }
    return bytes.takeBytes();
  }
}

class _SshKeyExchangeResult {
  const _SshKeyExchangeResult({
    required this.handshake,
    required this.negotiatedAlgorithms,
  });

  final SshHandshakeInfo handshake;
  final SshNegotiatedAlgorithms negotiatedAlgorithms;
}
