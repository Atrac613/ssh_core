enum SshForwardingMode { local, remote, dynamic }

class SshForwardTarget {
  const SshForwardTarget({required this.host, required this.port});

  final String host;
  final int port;
}

class SshForwardRequest {
  const SshForwardRequest._({
    required this.mode,
    required this.bindHost,
    required this.bindPort,
    this.target,
  });

  const SshForwardRequest.local({
    required String bindHost,
    required int bindPort,
    required SshForwardTarget target,
  }) : this._(
          mode: SshForwardingMode.local,
          bindHost: bindHost,
          bindPort: bindPort,
          target: target,
        );

  const SshForwardRequest.remote({
    required String bindHost,
    required int bindPort,
    required SshForwardTarget target,
  }) : this._(
          mode: SshForwardingMode.remote,
          bindHost: bindHost,
          bindPort: bindPort,
          target: target,
        );

  const SshForwardRequest.dynamic({
    required String bindHost,
    required int bindPort,
  }) : this._(
          mode: SshForwardingMode.dynamic,
          bindHost: bindHost,
          bindPort: bindPort,
        );

  final SshForwardingMode mode;
  final String bindHost;
  final int bindPort;
  final SshForwardTarget? target;
}

abstract class SshPortForward {
  SshForwardingMode get mode;

  String get bindHost;

  int get bindPort;

  Future<void> close();
}

abstract class SshPortForwardingService {
  Future<SshPortForward> openForward(SshForwardRequest request);
}
