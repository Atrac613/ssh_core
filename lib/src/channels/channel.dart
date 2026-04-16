enum SshChannelType { session, directTcpip, forwardedTcpip, x11, custom }

class SshChannelWindow {
  const SshChannelWindow({
    this.initialSize = 2 * 1024 * 1024,
    this.maxPacketSize = 32 * 1024,
  });

  final int initialSize;
  final int maxPacketSize;
}

class SshChannelOpenRequest {
  const SshChannelOpenRequest({
    required this.type,
    this.subtype,
    this.localWindow = const SshChannelWindow(),
    this.payload = const <String, Object?>{},
  });

  const SshChannelOpenRequest.session({
    this.localWindow = const SshChannelWindow(),
    this.payload = const <String, Object?>{},
  }) : type = SshChannelType.session,
       subtype = null;

  final SshChannelType type;
  final String? subtype;
  final SshChannelWindow localWindow;
  final Map<String, Object?> payload;
}

class SshChannelRequest {
  const SshChannelRequest({
    required this.type,
    this.wantReply = false,
    this.payload = const <String, Object?>{},
  });

  final String type;
  final bool wantReply;
  final Map<String, Object?> payload;
}

abstract class SshChannel {
  int get id;

  SshChannelType get type;

  Future<void> sendRequest(SshChannelRequest request);

  Future<void> close();
}

abstract class SshChannelFactory {
  Future<SshChannel> openChannel(SshChannelOpenRequest request);
}
