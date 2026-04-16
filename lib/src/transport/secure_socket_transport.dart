import 'dart:async';
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

class SshSecureSocketTransport implements SshPacketTransport {
  SshSecureSocketTransport({
    this.bannerExchange = const SshBannerExchange(),
    this.tcpNoDelay = true,
    Random? random,
    List<String> keyExchangeAlgorithms = const <String>[
      sshCurve25519Sha256,
      sshCurve25519Sha256LibSsh,
    ],
    List<String> serverHostKeyAlgorithms = const <String>[
      sshEd25519HostKeyAlgorithm,
      sshEcdsaSha2Nistp256HostKeyAlgorithm,
      sshRsaSha512HostKeyAlgorithm,
      sshRsaSha256HostKeyAlgorithm,
    ],
    List<String> encryptionAlgorithms = const <String>[
      sshAes256CtrCipher,
      sshAes192CtrCipher,
      sshAes128CtrCipher,
    ],
    List<String> macAlgorithms = const <String>[
      sshHmacSha512Mac,
      sshHmacSha256Mac,
    ],
    List<String> compressionAlgorithms = const <String>[sshNoCompression],
  })  : _random = random ?? Random.secure(),
        keyExchangeAlgorithms = List.unmodifiable(keyExchangeAlgorithms),
        serverHostKeyAlgorithms = List.unmodifiable(serverHostKeyAlgorithms),
        encryptionAlgorithms = List.unmodifiable(encryptionAlgorithms),
        macAlgorithms = List.unmodifiable(macAlgorithms),
        compressionAlgorithms = List.unmodifiable(compressionAlgorithms);

  final SshBannerExchange bannerExchange;
  final bool tcpNoDelay;
  final Random _random;
  final List<String> keyExchangeAlgorithms;
  final List<String> serverHostKeyAlgorithms;
  final List<String> encryptionAlgorithms;
  final List<String> macAlgorithms;
  final List<String> compressionAlgorithms;

  Socket? _socket;
  StreamIterator<List<int>>? _incoming;
  final List<int> _incomingBuffer = <int>[];
  SshPacketWriterState _writerState = SshPlainPacketWriterState();
  SshPacketReaderState _readerState = SshPlainPacketReaderState();
  SshHandshakeInfo? _handshake;
  SshTransportState _state = SshTransportState.disconnected;

  @override
  SshTransportState get state => _state;

  Socket? get socket => _socket;

  SshHandshakeInfo? get handshake => _handshake;

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
      _writerState = SshPlainPacketWriterState();
      _readerState = SshPlainPacketReaderState();

      final SshBannerExchangeResult exchange = await _exchangeBanners(
        localIdentification: settings.clientIdentification,
      );
      final SshHandshakeInfo handshake = await _runKeyExchange(
        exchange: exchange,
      );

      _handshake = handshake;
      _state = SshTransportState.connected;
      return handshake;
    } catch (_) {
      _handshake = null;
      _state = SshTransportState.disconnected;
      await _closeResources();
      rethrow;
    }
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {
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
        'SSH global request payload must be a byte list.',
      );
    }

    await writePacket(
      SshGlobalRequestMessage(
        requestName: request.type,
        wantReply: request.wantReply,
        requestData: requestData,
      ).encodePayload(),
    );
  }

  @override
  Future<void> disconnect() async {
    _state = SshTransportState.closed;
    _handshake = null;
    await _closeResources();
  }

  @override
  Future<SshBinaryPacket> readPacket() async {
    _ensureConnected();
    return _readPacketWithState(_readerState);
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
    await writeBytes(_writerState.encode(payload));
  }

  Future<SshBannerExchangeResult> _exchangeBanners({
    required String localIdentification,
  }) async {
    await writeBytes(
        utf8.encode(bannerExchange.formatLocalLine(localIdentification)));

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

  Future<SshHandshakeInfo> _runKeyExchange({
    required SshBannerExchangeResult exchange,
  }) async {
    final SshKexInitMessage clientKexInit = _buildClientKexInit();
    await _writePlainPacket(clientKexInit.encodePayload());

    final SshKexInitMessage serverKexInit = SshKexInitMessage.decodePayload(
      (await _readPacketWithState(SshPlainPacketReaderState())).payload,
    );

    final SshNegotiatedAlgorithms negotiatedAlgorithms =
        const SshAlgorithmNegotiator().negotiate(
      clientProposal: clientKexInit,
      serverProposal: serverKexInit,
    );
    _validateNegotiatedAlgorithms(negotiatedAlgorithms);

    if (negotiatedAlgorithms.ignoreGuessedServerPacket) {
      await _readPacketWithState(SshPlainPacketReaderState());
    }

    final SshCurve25519KeyPair keyPair = SshCurve25519KeyPair.generate(_random);
    await _writePlainPacket(
      SshKexEcdhInitMessage(
        clientEphemeralPublicKey: keyPair.publicKey,
      ).encodePayload(),
    );

    final SshKexEcdhReplyMessage reply = SshKexEcdhReplyMessage.decodePayload(
      (await _readPacketWithState(SshPlainPacketReaderState())).payload,
    );
    final BigInt sharedSecret = keyPair.computeSharedSecret(
      reply.serverEphemeralPublicKey,
    );
    final Uint8List exchangeHash =
        const SshExchangeHashComputer().sha256FromInput(
      SshKexEcdhExchangeHashInput(
        clientIdentification: exchange.localBanner.value,
        serverIdentification: exchange.remoteBanner.value,
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

    await _writePlainPacket(const SshNewKeysMessage().encodePayload());
    SshNewKeysMessage.decodePayload(
      (await _readPacketWithState(SshPlainPacketReaderState())).payload,
    );

    final int clientIvLength = sshCipherBlockSize(
      negotiatedAlgorithms.encryptionClientToServer,
    );
    final int serverIvLength = sshCipherBlockSize(
      negotiatedAlgorithms.encryptionServerToClient,
    );
    final int clientKeyLength = sshCipherKeyLength(
      negotiatedAlgorithms.encryptionClientToServer,
    );
    final int serverKeyLength = sshCipherKeyLength(
      negotiatedAlgorithms.encryptionServerToClient,
    );
    final int clientMacKeyLength = sshMacKeyLength(
      negotiatedAlgorithms.macClientToServer,
    );
    final int serverMacKeyLength = sshMacKeyLength(
      negotiatedAlgorithms.macServerToClient,
    );
    final SshDerivedKeys derivedKeys = const SshKeyDerivation().deriveSha256(
      context: SshKeyDerivationContext(
        sharedSecret: sharedSecret,
        exchangeHash: exchangeHash,
        sessionIdentifier: exchangeHash,
      ),
      ivLength: max(clientIvLength, serverIvLength),
      encryptionKeyLength: max(clientKeyLength, serverKeyLength),
      integrityKeyLength: max(clientMacKeyLength, serverMacKeyLength),
    );

    _writerState = SshAesCtrHmacPacketWriterState(
      encryptionKey: derivedKeys.encryptionKeyClientToServer.sublist(
        0,
        clientKeyLength,
      ),
      initialVector: derivedKeys.initialIvClientToServer.sublist(
        0,
        clientIvLength,
      ),
      macKey: derivedKeys.integrityKeyClientToServer.sublist(
        0,
        clientMacKeyLength,
      ),
      macAlgorithm: negotiatedAlgorithms.macClientToServer,
      codec: SshPacketCodec(blockSize: clientIvLength),
    );
    _readerState = SshAesCtrHmacPacketReaderState(
      encryptionKey: derivedKeys.encryptionKeyServerToClient.sublist(
        0,
        serverKeyLength,
      ),
      initialVector: derivedKeys.initialIvServerToClient.sublist(
        0,
        serverIvLength,
      ),
      macKey: derivedKeys.integrityKeyServerToClient.sublist(
        0,
        serverMacKeyLength,
      ),
      macAlgorithm: negotiatedAlgorithms.macServerToClient,
      codec: SshPacketCodec(blockSize: serverIvLength),
    );

    return SshHandshakeInfo(
      localIdentification: exchange.localBanner.value,
      remoteIdentification: exchange.remoteBanner.value,
      negotiatedAlgorithms: negotiatedAlgorithms.asHandshakeMap(),
      sessionIdentifier: exchangeHash,
      hostKey: reply.hostKey,
    );
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
    switch (negotiated.keyExchange) {
      case sshCurve25519Sha256:
      case sshCurve25519Sha256LibSsh:
        break;
      default:
        throw SshTransportCryptoException(
          'Unsupported SSH key exchange algorithm: ${negotiated.keyExchange}.',
        );
    }

    switch (negotiated.serverHostKey) {
      case sshEd25519HostKeyAlgorithm:
      case sshRsaHostKeyType:
      case sshRsaSha256HostKeyAlgorithm:
      case sshRsaSha512HostKeyAlgorithm:
      case sshEcdsaSha2Nistp256HostKeyAlgorithm:
        break;
      default:
        throw SshTransportCryptoException(
          'Unsupported SSH host key algorithm: ${negotiated.serverHostKey}.',
        );
    }

    sshCipherKeyLength(negotiated.encryptionClientToServer);
    sshCipherKeyLength(negotiated.encryptionServerToClient);
    sshMacKeyLength(negotiated.macClientToServer);
    sshMacKeyLength(negotiated.macServerToClient);

    if (negotiated.compressionClientToServer != sshNoCompression ||
        negotiated.compressionServerToClient != sshNoCompression) {
      throw const SshTransportCryptoException(
        'Only "none" SSH compression is currently supported.',
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
