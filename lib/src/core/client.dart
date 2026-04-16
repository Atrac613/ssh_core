import '../auth/auth.dart';
import '../channels/channel.dart';
import '../exec/exec.dart';
import '../forwarding/port_forwarding.dart';
import '../pty/pty.dart';
import '../sessions/session.dart';
import '../sftp/sftp.dart';
import '../transport/host_key.dart';
import '../transport/transport.dart';
import 'config.dart';
import 'exceptions.dart';

class SshClient {
  SshClient({
    required this.config,
    required List<SshAuthMethod> authMethods,
    required this.transport,
    required this.authenticator,
    required this.channelFactory,
    required this.sessionManager,
    required this.execService,
    required this.sftpSubsystem,
    required this.portForwardingService,
  }) : authMethods = List.unmodifiable(authMethods);

  final SshClientConfig config;
  final List<SshAuthMethod> authMethods;
  final SshTransport transport;
  final SshAuthenticator authenticator;
  final SshChannelFactory channelFactory;
  final SshSessionManager sessionManager;
  final SshExecService execService;
  final SftpSubsystem sftpSubsystem;
  final SshPortForwardingService portForwardingService;

  SshClientState _state = SshClientState.idle;

  SshClientState get state => _state;

  bool get isConnected => _state == SshClientState.connected;

  Future<void> connect() async {
    _expectState([SshClientState.idle, SshClientState.closed]);
    _state = SshClientState.connecting;

    try {
      final SshHandshakeInfo handshake = await transport.connect(
        endpoint: config.endpoint,
        settings: config.transport,
      );
      await _verifyHostKeyIfNeeded(handshake);
      final result = await authenticator.authenticate(
        context: SshAuthContext(
          config: config,
          transport: transport,
          handshake: handshake,
        ),
        methods: authMethods,
      );

      if (!result.isSuccess) {
        throw SshAuthException(result.message ?? 'SSH authentication failed.');
      }

      _state = SshClientState.connected;
    } catch (error) {
      _state = SshClientState.idle;
      rethrow;
    }
  }

  Future<SshChannel> openChannel(SshChannelOpenRequest request) async {
    _expectConnected();
    return channelFactory.openChannel(request);
  }

  Future<SshShellSession> openShell({
    SshPtyConfig? pty,
    Map<String, String> environment = const <String, String>{},
  }) async {
    _expectConnected();
    return sessionManager.openShellSession(
      SshShellRequest(environment: environment, pty: pty),
    );
  }

  Future<SshExecResult> exec(
    String command, {
    Map<String, String> environment = const <String, String>{},
    SshPtyConfig? pty,
    bool forwardAgent = false,
  }) async {
    _expectConnected();
    return execService.exec(
      SshExecRequest(
        command: command,
        environment: environment,
        pty: pty,
        forwardAgent: forwardAgent,
      ),
    );
  }

  Future<SftpClient> openSftp() async {
    _expectConnected();
    return sftpSubsystem.open();
  }

  Future<SshPortForward> forwardLocal({
    required String bindHost,
    required int bindPort,
    required String targetHost,
    required int targetPort,
  }) async {
    _expectConnected();
    return portForwardingService.openForward(
      SshForwardRequest.local(
        bindHost: bindHost,
        bindPort: bindPort,
        target: SshForwardTarget(host: targetHost, port: targetPort),
      ),
    );
  }

  Future<SshPortForward> forwardRemote({
    required String bindHost,
    required int bindPort,
    required String targetHost,
    required int targetPort,
  }) async {
    _expectConnected();
    return portForwardingService.openForward(
      SshForwardRequest.remote(
        bindHost: bindHost,
        bindPort: bindPort,
        target: SshForwardTarget(host: targetHost, port: targetPort),
      ),
    );
  }

  Future<SshPortForward> forwardDynamic({
    required String bindHost,
    required int bindPort,
  }) async {
    _expectConnected();
    return portForwardingService.openForward(
      SshForwardRequest.dynamic(bindHost: bindHost, bindPort: bindPort),
    );
  }

  Future<void> close() async {
    if (_state == SshClientState.closed || _state == SshClientState.idle) {
      _state = SshClientState.closed;
      return;
    }

    _state = SshClientState.closing;
    await transport.disconnect();
    _state = SshClientState.closed;
  }

  void _expectConnected() {
    _expectState([SshClientState.connected]);
  }

  void _expectState(List<SshClientState> allowedStates) {
    if (allowedStates.contains(_state)) {
      return;
    }

    throw SshStateException(
      'Invalid SSH client state: $_state. '
      'Allowed states: ${allowedStates.join(', ')}.',
    );
  }

  Future<void> _verifyHostKeyIfNeeded(SshHandshakeInfo handshake) async {
    final SshHostKeyVerifier? verifier = config.hostKeyVerifier;
    if (verifier == null) {
      return;
    }

    final SshHostKey? hostKey = handshake.hostKey;
    if (hostKey == null) {
      throw const SshHostKeyException(
        'SSH transport did not provide a host key for verification.',
      );
    }

    final SshHostKeyVerificationResult result = await verifier.verify(
      SshHostKeyVerificationContext(
        host: config.host,
        port: config.port,
        localIdentification: handshake.localIdentification,
        remoteIdentification: handshake.remoteIdentification,
        hostKey: hostKey,
      ),
    );

    if (!result.isSuccess) {
      throw SshHostKeyException(
        result.message ?? 'SSH host key verification failed.',
      );
    }
  }
}
