import 'dart:convert';
import 'dart:io';

import 'package:ssh_core/ssh_core_io.dart';

Future<void> main() async {
  final Map<String, String> environment = Platform.environment;
  final String? host = environment['SSH_CORE_HOST'];
  final String? username = environment['SSH_CORE_USERNAME'];
  final String? password = environment['SSH_CORE_PASSWORD'];

  if (host == null || username == null || password == null) {
    stdout.writeln(
      'Set SSH_CORE_HOST, SSH_CORE_USERNAME, and SSH_CORE_PASSWORD to run '
      'the live IO example. Optional: SSH_CORE_PORT, '
      'SSH_CORE_HOST_KEY_BASE64, SSH_CORE_SFTP_PATH, '
      'SSH_CORE_FORWARD_TARGET_HOST, SSH_CORE_FORWARD_TARGET_PORT.',
    );
    return;
  }

  final int port = int.tryParse(environment['SSH_CORE_PORT'] ?? '') ?? 22;
  final SshClient client = SshIoClientFactory.create(
    config: SshClientConfig(
      host: host,
      port: port,
      username: username,
      hostKeyVerifier: _hostKeyVerifier(
        host: host,
        port: port,
        encodedHostKey: environment['SSH_CORE_HOST_KEY_BASE64'],
      ),
    ),
    authMethods: <SshAuthMethod>[
      SshPasswordAuthMethod(password: password),
    ],
  );

  try {
    await client.connect();

    final SshExecResult execResult = await client.exec('uname -a');
    stdout.writeln('exec: ${execResult.stdoutText.trim()}');

    final SftpClient sftp = await client.openSftp();
    try {
      final String directory = environment['SSH_CORE_SFTP_PATH'] ?? '.';
      final List<SftpFileEntry> entries = await sftp.listDirectory(directory);
      for (final SftpFileEntry entry in entries.take(5)) {
        stdout.writeln('sftp: ${entry.path} (${entry.type.name})');
      }
    } finally {
      await sftp.close();
    }

    final String? forwardTargetHost =
        environment['SSH_CORE_FORWARD_TARGET_HOST'];
    final int? forwardTargetPort = int.tryParse(
      environment['SSH_CORE_FORWARD_TARGET_PORT'] ?? '',
    );
    if (forwardTargetHost != null && forwardTargetPort != null) {
      final SshPortForward forward = await client.forwardLocal(
        bindHost: '127.0.0.1',
        bindPort: 0,
        targetHost: forwardTargetHost,
        targetPort: forwardTargetPort,
      );
      stdout.writeln(
        'forward: ${forward.bindHost}:${forward.bindPort} '
        '-> $forwardTargetHost:$forwardTargetPort',
      );
      await forward.close();
    }
  } finally {
    await client.close();
  }
}

SshHostKeyVerifier? _hostKeyVerifier({
  required String host,
  required int port,
  required String? encodedHostKey,
}) {
  final String? base64HostKey = encodedHostKey;
  if (base64HostKey == null || base64HostKey.isEmpty) {
    return null;
  }

  return SshStaticHostKeyVerifier(
    trustedKeys: <SshTrustedHostKey>[
      SshTrustedHostKey(
        host: host,
        port: port,
        hostKey: SshHostKey.decode(base64.decode(base64HostKey)),
      ),
    ],
  );
}
