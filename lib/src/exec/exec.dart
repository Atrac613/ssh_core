import 'dart:convert';

import '../pty/pty.dart';

class SshExecRequest {
  const SshExecRequest({
    required this.command,
    this.environment = const <String, String>{},
    this.pty,
    this.forwardAgent = false,
  });

  final String command;
  final Map<String, String> environment;
  final SshPtyConfig? pty;
  final bool forwardAgent;
}

class SshExecResult {
  const SshExecResult({
    required this.exitCode,
    this.stdout = const <int>[],
    this.stderr = const <int>[],
  });

  final int exitCode;
  final List<int> stdout;
  final List<int> stderr;

  String get stdoutText => utf8.decode(stdout, allowMalformed: true);

  String get stderrText => utf8.decode(stderr, allowMalformed: true);
}

abstract class SshExecService {
  Future<SshExecResult> exec(SshExecRequest request);
}
