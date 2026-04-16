import '../channels/channel.dart';
import '../pty/pty.dart';

enum SshSessionState { opening, active, closing, closed }

class SshShellRequest {
  const SshShellRequest({
    this.pty,
    this.environment = const <String, String>{},
  });

  final SshPtyConfig? pty;
  final Map<String, String> environment;
}

abstract class SshShellSession {
  SshChannel get channel;

  SshSessionState get state;

  Stream<List<int>> get stdout;

  Stream<List<int>> get stderr;

  Future<void> writeStdin(List<int> data);

  Future<void> resizePty(SshPtyConfig nextPty);

  Future<void> close();
}

abstract class SshSessionManager {
  Future<SshShellSession> openShellSession(SshShellRequest request);
}
