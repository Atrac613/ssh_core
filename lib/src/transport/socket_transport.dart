import 'dart:io';

import 'transport.dart';

class SshSocketTransport implements SshTransport {
  SshSocketTransport({
    this.bannerExchange = const SshBannerExchange(),
    this.packetCodec = const SshPacketCodec(),
    this.tcpNoDelay = true,
  });

  final SshBannerExchange bannerExchange;
  final SshPacketCodec packetCodec;
  final bool tcpNoDelay;

  Socket? _socket;
  SshTransportStream? _transportStream;
  SshHandshakeInfo? _handshake;
  SshTransportState _state = SshTransportState.disconnected;

  @override
  SshTransportState get state => _state;

  Socket? get socket => _socket;

  SshTransportStream? get transportStream => _transportStream;

  SshHandshakeInfo? get handshake => _handshake;

  bool get isConnected => _state == SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    if (_state == SshTransportState.connecting ||
        _state == SshTransportState.connected) {
      throw StateError('SSH socket transport is already connected.');
    }

    _state = SshTransportState.connecting;
    Socket? socket;
    SshTransportStream? transportStream;

    try {
      socket = await Socket.connect(
        endpoint.host,
        endpoint.port,
        timeout: settings.connectTimeout,
      );

      if (tcpNoDelay) {
        socket.setOption(SocketOption.tcpNoDelay, true);
      }

      transportStream = SshTransportStream(
        incoming: socket,
        onWrite: (List<int> bytes) {
          socket!.add(bytes);
          return socket.flush();
        },
        onClose: () async {
          await socket!.close();
          socket.destroy();
        },
        bannerExchange: bannerExchange,
        packetCodec: packetCodec,
      );

      final SshBannerExchangeResult exchange =
          await transportStream.exchangeBanners(
        localIdentification: settings.clientIdentification,
      );

      final SshHandshakeInfo handshake = SshHandshakeInfo.fromBannerExchange(
        exchange,
      );

      _socket = socket;
      _transportStream = transportStream;
      _handshake = handshake;
      _state = SshTransportState.connected;

      return handshake;
    } catch (_) {
      _handshake = null;
      _transportStream = null;
      _socket = null;
      _state = SshTransportState.disconnected;

      if (transportStream != null) {
        await transportStream.close();
      } else if (socket != null) {
        await socket.close();
        socket.destroy();
      }

      rethrow;
    }
  }

  Future<SshBinaryPacket> readPacket() async {
    final SshTransportStream transportStream = _requireStream();
    return transportStream.readPacket();
  }

  Future<void> writePacket(List<int> payload) async {
    final SshTransportStream transportStream = _requireStream();
    await transportStream.writePacket(payload);
  }

  Future<void> writeBytes(List<int> bytes) async {
    final SshTransportStream transportStream = _requireStream();
    await transportStream.writeBytes(bytes);
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {
    throw UnsupportedError(
      'SSH global request encoding is not implemented yet.',
    );
  }

  @override
  Future<void> disconnect() async {
    final SshTransportStream? transportStream = _transportStream;
    final Socket? socket = _socket;

    _transportStream = null;
    _socket = null;
    _handshake = null;
    _state = SshTransportState.closed;

    if (transportStream != null) {
      await transportStream.close();
      return;
    }

    if (socket != null) {
      await socket.close();
      socket.destroy();
    }
  }

  SshTransportStream _requireStream() {
    final SshTransportStream? transportStream = _transportStream;
    if (transportStream == null || _state != SshTransportState.connected) {
      throw StateError('SSH socket transport is not connected.');
    }
    return transportStream;
  }
}
