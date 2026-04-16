import 'dart:async';
import 'dart:io';

import '../channels/channel.dart';
import '../channels/packet_channel.dart';
import '../transport/transport.dart';
import 'port_forwarding.dart';
import 'protocol_port_forwarding.dart';
import 'socks.dart';

class SshIoPortForwardingService implements SshPortForwardingService {
  SshIoPortForwardingService({
    required SshTransport transport,
    required SshPacketChannelFactory channelFactory,
  })  : _transport = transport,
        _channelFactory = channelFactory,
        _protocolService =
            SshProtocolPortForwardingService(transport: transport);

  final SshTransport _transport;
  final SshPacketChannelFactory _channelFactory;
  final SshProtocolPortForwardingService _protocolService;

  @override
  Future<SshPortForward> openForward(SshForwardRequest request) {
    switch (request.mode) {
      case SshForwardingMode.local:
        return _openLocalForward(request);
      case SshForwardingMode.remote:
        return _openRemoteForward(request);
      case SshForwardingMode.dynamic:
        return _openDynamicForward(request);
    }
  }

  Future<SshPortForward> _openLocalForward(SshForwardRequest request) async {
    final SshForwardTarget target = _requireTarget(request);
    final ServerSocket server = await ServerSocket.bind(
      request.bindHost,
      request.bindPort,
    );
    final StreamSubscription<Socket> subscription = server.listen(
      (Socket socket) {
        unawaited(
          _handleForwardedSocket(
            socket: socket,
            targetHost: target.host,
            targetPort: target.port,
          ),
        );
      },
    );

    return _SshIoPortForward.local(
      transport: _transport,
      server: server,
      subscription: subscription,
    );
  }

  Future<SshPortForward> _openDynamicForward(SshForwardRequest request) async {
    final ServerSocket server = await ServerSocket.bind(
      request.bindHost,
      request.bindPort,
    );
    final StreamSubscription<Socket> subscription = server.listen(
      (Socket socket) {
        unawaited(
          _handleDynamicSocket(
            socket: socket,
            bindHost: request.bindHost,
            bindPort: server.port,
          ),
        );
      },
    );

    return _SshIoPortForward.dynamic(
      transport: _transport,
      server: server,
      subscription: subscription,
    );
  }

  Future<SshPortForward> _openRemoteForward(SshForwardRequest request) async {
    if (request.bindPort == 0) {
      throw UnsupportedError(
        'Remote forwarding requires an explicit bind port in the IO bridge.',
      );
    }

    final SshForwardTarget target = _requireTarget(request);
    final SshPortForward controlForward = await _protocolService.openForward(
      request,
    );
    final StreamSubscription<SshInboundPacketChannel> subscription =
        _channelFactory.inboundChannels
            .listen((SshInboundPacketChannel inbound) {
      if (inbound.openRequest.type != SshChannelType.forwardedTcpip) {
        return;
      }

      final int? connectedPort =
          inbound.openRequest.payload['connectedPort'] as int?;
      if (connectedPort != request.bindPort) {
        return;
      }

      unawaited(
        _handleRemoteInboundChannel(
          channel: inbound.channel,
          targetHost: target.host,
          targetPort: target.port,
        ),
      );
    });

    return _SshIoRemotePortForward(
      controlForward: controlForward,
      subscription: subscription,
    );
  }

  Future<void> _handleForwardedSocket({
    required Socket socket,
    required String targetHost,
    required int targetPort,
  }) async {
    try {
      final SshPacketChannel channel = await _channelFactory.openChannel(
        SshChannelOpenRequest(
          type: SshChannelType.directTcpip,
          payload: <String, Object?>{
            'targetHost': targetHost,
            'targetPort': targetPort,
            'originatorHost': socket.remoteAddress.address,
            'originatorPort': socket.remotePort,
          },
        ),
      ) as SshPacketChannel;
      await _bridgeSocketAndChannel(socket, channel);
    } catch (_) {
      await socket.close();
      socket.destroy();
    }
  }

  Future<void> _handleDynamicSocket({
    required Socket socket,
    required String bindHost,
    required int bindPort,
  }) async {
    try {
      final SshSocks5Greeting greeting = SshSocks5Greeting.decode(
        await _readSocksMessage(
          socket: socket,
          expectedLength: (List<int> buffer) {
            if (buffer.length < 2) {
              return null;
            }
            return 2 + buffer[1];
          },
        ),
      );
      final SshSocks5AuthMethod selectedMethod =
          greeting.methods.contains(SshSocks5AuthMethod.noAuth)
              ? SshSocks5AuthMethod.noAuth
              : SshSocks5AuthMethod.noAcceptableMethods;
      socket.add(SshSocks5MethodSelection(method: selectedMethod).encode());
      await socket.flush();

      if (selectedMethod == SshSocks5AuthMethod.noAcceptableMethods) {
        await socket.close();
        socket.destroy();
        return;
      }

      final SshSocks5Request request = SshSocks5Request.decode(
        await _readSocksMessage(
          socket: socket,
          expectedLength: (List<int> buffer) {
            if (buffer.length < 4) {
              return null;
            }
            switch (buffer[3]) {
              case 0x01:
                return 10;
              case 0x03:
                if (buffer.length < 5) {
                  return null;
                }
                return 7 + buffer[4];
              case 0x04:
                return 22;
              default:
                throw const FormatException(
                  'Unsupported SOCKS5 address type.',
                );
            }
          },
        ),
      );

      if (request.command != SshSocks5Command.connect) {
        socket.add(
          SshSocks5Reply(
            replyCode: SshSocks5ReplyCode.commandNotSupported,
            boundAddress: _socksAddressForHost(bindHost),
            boundPort: bindPort,
          ).encode(),
        );
        await socket.flush();
        await socket.close();
        socket.destroy();
        return;
      }

      final SshPacketChannel channel = await _channelFactory.openChannel(
        SshChannelOpenRequest(
          type: SshChannelType.directTcpip,
          payload: <String, Object?>{
            'targetHost': request.destinationAddress.host,
            'targetPort': request.destinationPort,
            'originatorHost': socket.remoteAddress.address,
            'originatorPort': socket.remotePort,
          },
        ),
      ) as SshPacketChannel;
      socket.add(
        SshSocks5Reply(
          replyCode: SshSocks5ReplyCode.succeeded,
          boundAddress: _socksAddressForHost(bindHost),
          boundPort: bindPort,
        ).encode(),
      );
      await socket.flush();
      await _bridgeSocketAndChannel(socket, channel);
    } catch (_) {
      await socket.close();
      socket.destroy();
    }
  }

  Future<void> _handleRemoteInboundChannel({
    required SshPacketChannel channel,
    required String targetHost,
    required int targetPort,
  }) async {
    Socket? socket;
    try {
      socket = await Socket.connect(targetHost, targetPort);
      await _bridgeSocketAndChannel(socket, channel);
    } catch (_) {
      await channel.close();
      if (socket != null) {
        await socket.close();
        socket.destroy();
      }
    }
  }

  Future<void> _bridgeSocketAndChannel(
    Socket socket,
    SshPacketChannel channel,
  ) async {
    final StreamSubscription<List<int>> socketSubscription = socket.listen(
      (List<int> data) {
        unawaited(channel.sendData(data));
      },
      onDone: () {
        unawaited(channel.sendEof());
        unawaited(channel.close());
      },
      onError: (_, __) {
        unawaited(channel.close());
      },
      cancelOnError: true,
    );
    final StreamSubscription<List<int>> stdoutSubscription =
        channel.stdout.listen(
      socket.add,
      onDone: () async {
        await socket.close();
        socket.destroy();
      },
      onError: (_, __) {
        socket.destroy();
      },
      cancelOnError: true,
    );
    final StreamSubscription<List<int>> stderrSubscription =
        channel.stderr.listen(
      (_) {},
    );

    await Future.any<dynamic>(<Future<dynamic>>[
      socket.done,
      channel.done,
    ]);
    await socketSubscription.cancel();
    await stdoutSubscription.cancel();
    await stderrSubscription.cancel();
    await socket.close();
    socket.destroy();
    await channel.close();
  }

  Future<List<int>> _readSocksMessage({
    required Socket socket,
    required int? Function(List<int> buffer) expectedLength,
  }) async {
    final StreamIterator<List<int>> iterator = StreamIterator<List<int>>(
      socket,
    );
    final List<int> buffer = <int>[];
    try {
      for (;;) {
        final int? length = expectedLength(buffer);
        if (length != null && buffer.length >= length) {
          return buffer.sublist(0, length);
        }

        final bool hasNext = await iterator.moveNext();
        if (!hasNext) {
          throw StateError(
              'SOCKS client closed before a full message arrived.');
        }
        buffer.addAll(iterator.current);
      }
    } finally {
      await iterator.cancel();
    }
  }

  SshForwardTarget _requireTarget(SshForwardRequest request) {
    final SshForwardTarget? target = request.target;
    if (target == null) {
      throw StateError('SSH forward request is missing a forwarding target.');
    }
    return target;
  }
}

class _SshIoPortForward implements SshPortForward {
  _SshIoPortForward._({
    required this.mode,
    required this.bindHost,
    required this.bindPort,
    required SshTransport transport,
    required ServerSocket server,
    required StreamSubscription<Socket> subscription,
  })  : _transport = transport,
        _server = server,
        _subscription = subscription;

  factory _SshIoPortForward.local({
    required SshTransport transport,
    required ServerSocket server,
    required StreamSubscription<Socket> subscription,
  }) {
    return _SshIoPortForward._(
      mode: SshForwardingMode.local,
      bindHost: server.address.address,
      bindPort: server.port,
      transport: transport,
      server: server,
      subscription: subscription,
    );
  }

  factory _SshIoPortForward.dynamic({
    required SshTransport transport,
    required ServerSocket server,
    required StreamSubscription<Socket> subscription,
  }) {
    return _SshIoPortForward._(
      mode: SshForwardingMode.dynamic,
      bindHost: server.address.address,
      bindPort: server.port,
      transport: transport,
      server: server,
      subscription: subscription,
    );
  }

  final SshTransport _transport;
  final ServerSocket _server;
  final StreamSubscription<Socket> _subscription;
  bool _closed = false;

  @override
  final SshForwardingMode mode;

  @override
  final String bindHost;

  @override
  final int bindPort;

  @override
  Future<void> close() async {
    if (_closed) {
      return;
    }

    _closed = true;
    await _subscription.cancel();
    await _server.close();
    if (_transport.state == SshTransportState.closed) {
      return;
    }
  }
}

class _SshIoRemotePortForward implements SshPortForward {
  _SshIoRemotePortForward({
    required SshPortForward controlForward,
    required StreamSubscription<SshInboundPacketChannel> subscription,
  })  : _controlForward = controlForward,
        _subscription = subscription;

  final SshPortForward _controlForward;
  final StreamSubscription<SshInboundPacketChannel> _subscription;
  bool _closed = false;

  @override
  SshForwardingMode get mode => _controlForward.mode;

  @override
  String get bindHost => _controlForward.bindHost;

  @override
  int get bindPort => _controlForward.bindPort;

  @override
  Future<void> close() async {
    if (_closed) {
      return;
    }

    _closed = true;
    await _subscription.cancel();
    await _controlForward.close();
  }
}

SshSocks5Address _socksAddressForHost(String host) {
  if (InternetAddress.tryParse(host)?.type == InternetAddressType.IPv6) {
    return SshSocks5Address.ipv6Bytes(
      addressBytes: InternetAddress(host).rawAddress,
      host: host,
    );
  }

  if (InternetAddress.tryParse(host) != null) {
    return SshSocks5Address.ipv4(host);
  }

  return SshSocks5Address.domain(host);
}
