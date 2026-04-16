import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssh_core/ssh_core_io.dart';

Future<void> main() async {
  await _exerciseTransportPrimitives();
  await _exerciseAuthProtocol();
  await _exerciseHostKeyVerification();
  await _exerciseSocketTransport();

  final SshHostKey trustedHostKey = _testHostKey();
  final client = SshClient(
    config: SshClientConfig(
      host: 'localhost',
      username: 'tester',
      hostKeyVerifier: SshStaticHostKeyVerifier(
        trustedKeys: <SshTrustedHostKey>[
          SshTrustedHostKey(host: 'localhost', hostKey: trustedHostKey),
        ],
      ),
    ),
    authMethods: const <SshAuthMethod>[SshPasswordAuthMethod(password: 'pw')],
    transport: _FakeTransport(hostKey: trustedHostKey),
    authenticator: _FakeAuthenticator(),
    channelFactory: _FakeChannelFactory(),
    sessionManager: _FakeSessionManager(),
    execService: _FakeExecService(),
    sftpSubsystem: _FakeSftpSubsystem(),
    portForwardingService: _FakePortForwardingService(),
  );

  assert(client.state == SshClientState.idle);

  await client.connect();
  assert(client.isConnected);

  final execResult = await client.exec('echo smoke');
  assert(execResult.exitCode == 0);
  assert(execResult.stdoutText.trim() == 'ok:echo smoke');

  final shell = await client.openShell(
    pty: const SshPtyConfig(columns: 120, rows: 40),
  );
  assert(shell.state == SshSessionState.active);

  final sftp = await client.openSftp();
  final files = await sftp.listDirectory('/tmp');
  assert(files.single.path == '/tmp/demo.txt');

  final localForward = await client.forwardLocal(
    bindHost: '127.0.0.1',
    bindPort: 10022,
    targetHost: '127.0.0.1',
    targetPort: 22,
  );
  assert(localForward.mode == SshForwardingMode.local);

  await localForward.close();
  await sftp.close();
  await shell.close();
  await client.close();

  assert(client.state == SshClientState.closed);
}

Future<void> _exerciseTransportPrimitives() async {
  final SshPacketCodec codec = SshPacketCodec(
    paddingBytesFactory: (int length) =>
        List<int>.generate(length, (int i) => i),
  );
  final SshTransportBuffer transportBuffer = SshTransportBuffer(
    packetCodec: codec,
  );
  transportBuffer.add(
    utf8.encode(
        'prelude one\r\nprelude two\r\nSSH-2.0-demo-server integration\r\n'),
  );

  final List<String> remoteLines = <String>[];
  for (;;) {
    final String? line = transportBuffer.readLine();
    if (line == null) {
      break;
    }
    remoteLines.add(line);
  }

  assert(remoteLines.length == 3);
  assert(transportBuffer.pendingByteCount == 0);

  final SshBannerExchange bannerExchange = const SshBannerExchange();
  final SshBannerExchangeResult exchange = bannerExchange.resolve(
    localIdentification: 'SSH-2.0-ssh_core-test',
    remoteLines: remoteLines,
  );

  assert(exchange.localBanner.protocolVersion == '2.0');
  assert(exchange.remoteBanner.softwareVersion == 'demo-server');
  assert(exchange.ignoredLines.length == 2);
  assert(
    bannerExchange.formatLocalLine('SSH-2.0-ssh_core-test') ==
        'SSH-2.0-ssh_core-test\r\n',
  );

  final Uint8List frame = codec.encode(<int>[94, 1, 2, 3]);

  transportBuffer.add(frame.sublist(0, 3));
  assert(transportBuffer.readPacket() == null);
  transportBuffer.add(frame.sublist(3));

  final SshBinaryPacket? packet = transportBuffer.readPacket();
  assert(packet != null);
  final SshBinaryPacket decodedPacket = packet!;
  assert(decodedPacket.messageId == 94);
  assert(decodedPacket.payload.length == 4);
  assert(decodedPacket.padding.length >= 4);
  assert(transportBuffer.pendingByteCount == 0);

  final List<List<int>> outboundWrites = <List<int>>[];
  final SshTransportStream transportStream = SshTransportStream(
    incoming: Stream<List<int>>.fromIterable(<List<int>>[
      utf8.encode('prelude one\r\nSSH-2.0-demo-server integration\r\n'),
      frame.sublist(0, 3),
      frame.sublist(3),
    ]),
    onWrite: (List<int> bytes) {
      outboundWrites.add(List<int>.from(bytes));
    },
    bannerExchange: bannerExchange,
    packetCodec: codec,
  );

  final SshBannerExchangeResult streamedExchange =
      await transportStream.exchangeBanners(
    localIdentification: 'SSH-2.0-ssh_core-test',
  );
  assert(streamedExchange.remoteBanner.softwareVersion == 'demo-server');
  assert(
    utf8.decode(outboundWrites.single) == 'SSH-2.0-ssh_core-test\r\n',
  );

  final SshBinaryPacket streamedPacket = await transportStream.readPacket();
  assert(streamedPacket.messageId == 94);
  assert(streamedPacket.payload.length == 4);
  assert(transportStream.pendingByteCount == 0);
  await transportStream.close();

  final SshKexInitMessage kexInit = SshKexInitMessage(
    cookie: List<int>.generate(16, (int i) => i),
    kexAlgorithms: const <String>['curve25519-sha256'],
    serverHostKeyAlgorithms: const <String>['ssh-ed25519'],
    encryptionAlgorithmsClientToServer: const <String>[
      'chacha20-poly1305@openssh.com',
    ],
    encryptionAlgorithmsServerToClient: const <String>[
      'chacha20-poly1305@openssh.com',
    ],
    macAlgorithmsClientToServer: const <String>['hmac-sha2-256'],
    macAlgorithmsServerToClient: const <String>['hmac-sha2-256'],
    compressionAlgorithmsClientToServer: const <String>['none'],
    compressionAlgorithmsServerToClient: const <String>['none'],
  );
  final Uint8List kexPayload = kexInit.encodePayload();
  final SshKexInitMessage decodedKexInit = SshKexInitMessage.decodePayload(
    kexPayload,
  );
  assert(decodedKexInit.kexAlgorithms.single == 'curve25519-sha256');
  assert(
    decodedKexInit.serverHostKeyAlgorithms.single == 'ssh-ed25519',
  );
  assert(decodedKexInit.cookie.length == 16);

  final SshPayloadWriter mpIntWriter = SshPayloadWriter()
    ..writeMpInt(BigInt.zero)
    ..writeMpInt(BigInt.from(0x123456))
    ..writeMpInt(BigInt.from(-129));
  final SshPayloadReader mpIntReader = SshPayloadReader(mpIntWriter.toBytes());
  final BigInt zeroMpInt = mpIntReader.readMpInt();
  final BigInt positiveMpInt = mpIntReader.readMpInt();
  final BigInt negativeMpInt = mpIntReader.readMpInt();
  assert(zeroMpInt == BigInt.zero);
  assert(positiveMpInt == BigInt.from(0x123456));
  assert(negativeMpInt == BigInt.from(-129));
  mpIntReader.expectDone();

  final SshKexEcdhInitMessage ecdhInit = SshKexEcdhInitMessage(
    clientEphemeralPublicKey: const <int>[1, 3, 3, 7],
  );
  final SshKexEcdhInitMessage decodedEcdhInit =
      SshKexEcdhInitMessage.decodePayload(ecdhInit.encodePayload());
  assert(
    _sameBytes(
      decodedEcdhInit.clientEphemeralPublicKey,
      ecdhInit.clientEphemeralPublicKey,
    ),
  );

  final SshHostKey hostKey = _testHostKey();
  final SshSignature signature = SshSignature(
    algorithm: 'ssh-ed25519',
    blob: const <int>[9, 7, 5, 3],
  );
  final SshSignature decodedSignature = SshSignature.decode(signature.encode());
  assert(decodedSignature.matches(signature));
  final SshKexEcdhReplyMessage ecdhReply = SshKexEcdhReplyMessage(
    hostKey: hostKey,
    serverEphemeralPublicKey: const <int>[2, 4, 6, 8],
    exchangeHashSignature: signature.encode(),
  );
  final SshKexEcdhReplyMessage decodedEcdhReply =
      SshKexEcdhReplyMessage.decodePayload(ecdhReply.encodePayload());
  assert(decodedEcdhReply.hostKey.matches(hostKey));
  assert(decodedEcdhReply.decodedExchangeHashSignature.matches(signature));
  assert(
    _sameBytes(
      decodedEcdhReply.serverEphemeralPublicKey,
      ecdhReply.serverEphemeralPublicKey,
    ),
  );
  assert(
    _sameBytes(
      decodedEcdhReply.exchangeHashSignature,
      signature.encode(),
    ),
  );

  final Uint8List exchangeHashInput = SshKexEcdhExchangeHashInput(
    clientIdentification: 'SSH-2.0-ssh_core-client',
    serverIdentification: 'SSH-2.0-ssh_core-server',
    clientKexInitPayload: kexInit.encodePayload(),
    serverKexInitPayload: decodedKexInit.encodePayload(),
    hostKey: hostKey,
    clientEphemeralPublicKey: ecdhInit.clientEphemeralPublicKey,
    serverEphemeralPublicKey: ecdhReply.serverEphemeralPublicKey,
    sharedSecret: BigInt.from(0x123456),
  ).encode();
  final SshPayloadReader exchangeHashReader =
      SshPayloadReader(exchangeHashInput);
  final String exchangeHashClientIdentification =
      exchangeHashReader.readString();
  final String exchangeHashServerIdentification =
      exchangeHashReader.readString();
  final Uint8List exchangeHashClientKexInit =
      exchangeHashReader.readStringBytes();
  final Uint8List exchangeHashServerKexInit =
      exchangeHashReader.readStringBytes();
  final Uint8List exchangeHashHostKey = exchangeHashReader.readStringBytes();
  final Uint8List exchangeHashClientEphemeral =
      exchangeHashReader.readStringBytes();
  final Uint8List exchangeHashServerEphemeral =
      exchangeHashReader.readStringBytes();
  final BigInt exchangeHashSharedSecret = exchangeHashReader.readMpInt();
  assert(exchangeHashClientIdentification == 'SSH-2.0-ssh_core-client');
  assert(exchangeHashServerIdentification == 'SSH-2.0-ssh_core-server');
  assert(_sameBytes(exchangeHashClientKexInit, kexInit.encodePayload()));
  assert(
    _sameBytes(exchangeHashServerKexInit, decodedKexInit.encodePayload()),
  );
  assert(_sameBytes(exchangeHashHostKey, hostKey.encodedBytes));
  assert(
    _sameBytes(exchangeHashClientEphemeral, ecdhInit.clientEphemeralPublicKey),
  );
  assert(
    _sameBytes(exchangeHashServerEphemeral, ecdhReply.serverEphemeralPublicKey),
  );
  assert(exchangeHashSharedSecret == BigInt.from(0x123456));
  exchangeHashReader.expectDone();

  final SshNewKeysMessage newKeys = const SshNewKeysMessage();
  final SshNewKeysMessage decodedNewKeys = SshNewKeysMessage.decodePayload(
    newKeys.encodePayload(),
  );
  assert(decodedNewKeys.encodePayload().single == SshMessageId.newKeys.value);

  final SshAlgorithmNegotiator negotiator = const SshAlgorithmNegotiator();
  final SshNegotiatedAlgorithms negotiatedAlgorithms = negotiator.negotiate(
    clientProposal: SshKexInitMessage(
      cookie: List<int>.filled(16, 1),
      kexAlgorithms: const <String>[
        'curve25519-sha256',
        'diffie-hellman-group14-sha256',
      ],
      serverHostKeyAlgorithms: const <String>['ssh-ed25519', 'rsa-sha2-256'],
      encryptionAlgorithmsClientToServer: const <String>[
        'aes256-ctr',
        'aes128-ctr',
      ],
      encryptionAlgorithmsServerToClient: const <String>[
        'aes256-ctr',
        'aes128-ctr',
      ],
      macAlgorithmsClientToServer: const <String>['hmac-sha2-512'],
      macAlgorithmsServerToClient: const <String>['hmac-sha2-256'],
      compressionAlgorithmsClientToServer: const <String>['none', 'zlib'],
      compressionAlgorithmsServerToClient: const <String>['none', 'zlib'],
      languagesClientToServer: const <String>['ja-JP', 'en-US'],
      languagesServerToClient: const <String>['en-US'],
    ),
    serverProposal: SshKexInitMessage(
      cookie: List<int>.filled(16, 2),
      kexAlgorithms: const <String>[
        'diffie-hellman-group14-sha256',
        'curve25519-sha256',
      ],
      serverHostKeyAlgorithms: const <String>['rsa-sha2-256', 'ssh-ed25519'],
      encryptionAlgorithmsClientToServer: const <String>['aes128-ctr'],
      encryptionAlgorithmsServerToClient: const <String>['aes128-ctr'],
      macAlgorithmsClientToServer: const <String>['hmac-sha2-512'],
      macAlgorithmsServerToClient: const <String>['hmac-sha2-256'],
      compressionAlgorithmsClientToServer: const <String>['zlib', 'none'],
      compressionAlgorithmsServerToClient: const <String>['none'],
      languagesClientToServer: const <String>['en-US'],
      languagesServerToClient: const <String>['fr-FR'],
      firstKexPacketFollows: true,
    ),
  );
  assert(negotiatedAlgorithms.keyExchange == 'curve25519-sha256');
  assert(negotiatedAlgorithms.serverHostKey == 'ssh-ed25519');
  assert(negotiatedAlgorithms.encryptionClientToServer == 'aes128-ctr');
  assert(negotiatedAlgorithms.encryptionServerToClient == 'aes128-ctr');
  assert(negotiatedAlgorithms.macClientToServer == 'hmac-sha2-512');
  assert(negotiatedAlgorithms.macServerToClient == 'hmac-sha2-256');
  assert(negotiatedAlgorithms.compressionClientToServer == 'none');
  assert(negotiatedAlgorithms.compressionServerToClient == 'none');
  assert(negotiatedAlgorithms.languageClientToServer == 'en-US');
  assert(negotiatedAlgorithms.languageServerToClient == null);
  assert(negotiatedAlgorithms.ignoreGuessedClientPacket == false);
  assert(negotiatedAlgorithms.ignoreGuessedServerPacket);
}

Future<void> _exerciseAuthProtocol() async {
  final SshServiceRequestMessage serviceRequest = SshServiceRequestMessage(
    serviceName: sshUserauthService,
  );
  final SshServiceRequestMessage decodedServiceRequest =
      SshServiceRequestMessage.decodePayload(serviceRequest.encodePayload());
  assert(decodedServiceRequest.serviceName == sshUserauthService);

  final SshServiceAcceptMessage serviceAccept = SshServiceAcceptMessage(
    serviceName: sshUserauthService,
  );
  final SshServiceAcceptMessage decodedServiceAccept =
      SshServiceAcceptMessage.decodePayload(serviceAccept.encodePayload());
  assert(decodedServiceAccept.serviceName == sshUserauthService);

  final SshUserAuthRequestMessage noneRequest =
      SshUserAuthRequestMessage.none(username: 'tester');
  final SshUserAuthRequestMessage decodedNoneRequest =
      SshUserAuthRequestMessage.decodePayload(noneRequest.encodePayload());
  assert(decodedNoneRequest.username == 'tester');
  assert(decodedNoneRequest.methodName == 'none');
  assert(decodedNoneRequest.methodPayload.isEmpty);

  final SshUserAuthRequestMessage passwordRequest =
      SshUserAuthRequestMessage.password(
    username: 'tester',
    password: 'pw',
  );
  final SshUserAuthRequestMessage decodedPasswordRequest =
      SshUserAuthRequestMessage.decodePayload(passwordRequest.encodePayload());
  assert(decodedPasswordRequest.methodName == 'password');
  final SshPayloadReader passwordReader = SshPayloadReader(
    decodedPasswordRequest.methodPayload,
  );
  final bool passwordChangeRequested = passwordReader.readBool();
  final String passwordValue = passwordReader.readString();
  assert(passwordChangeRequested == false);
  assert(passwordValue == 'pw');
  passwordReader.expectDone();

  final SshUserAuthFailureMessage failure = SshUserAuthFailureMessage(
    allowedMethods: const <String>['password', 'publickey'],
  );
  final SshUserAuthFailureMessage decodedFailure =
      SshUserAuthFailureMessage.decodePayload(failure.encodePayload());
  assert(decodedFailure.allowedMethods.length == 2);
  assert(decodedFailure.allowedMethods.first == 'password');
  assert(decodedFailure.partialSuccess == false);

  final SshUserAuthSuccessMessage success = const SshUserAuthSuccessMessage();
  final SshUserAuthSuccessMessage decodedSuccess =
      SshUserAuthSuccessMessage.decodePayload(success.encodePayload());
  assert(
    decodedSuccess.encodePayload().single == SshMessageId.userauthSuccess.value,
  );

  final SshUserAuthBannerMessage banner = SshUserAuthBannerMessage(
    message: 'Authorized access only',
    languageTag: 'en-US',
  );
  final SshUserAuthBannerMessage decodedBanner =
      SshUserAuthBannerMessage.decodePayload(banner.encodePayload());
  assert(decodedBanner.message == 'Authorized access only');
  assert(decodedBanner.languageTag == 'en-US');

  final SshUserAuthPkOkMessage pkOk = SshUserAuthPkOkMessage(
    algorithm: 'ssh-ed25519',
    publicKey: const <int>[1, 2, 3],
  );
  final SshUserAuthPkOkMessage decodedPkOk =
      SshUserAuthPkOkMessage.decodePayload(pkOk.encodePayload());
  assert(decodedPkOk.algorithm == 'ssh-ed25519');
  assert(_sameBytes(decodedPkOk.publicKey, pkOk.publicKey));

  final SshUserAuthInfoRequestMessage infoRequest =
      SshUserAuthInfoRequestMessage(
    name: 'Verification',
    instruction: 'Enter the one-time code.',
    prompts: const <SshKeyboardInteractivePrompt>[
      SshKeyboardInteractivePrompt(prompt: 'Code: ', echo: false),
    ],
  );
  final SshUserAuthInfoRequestMessage decodedInfoRequest =
      SshUserAuthInfoRequestMessage.decodePayload(infoRequest.encodePayload());
  assert(decodedInfoRequest.name == 'Verification');
  assert(decodedInfoRequest.prompts.single.prompt == 'Code: ');
  assert(decodedInfoRequest.prompts.single.echo == false);

  final SshUserAuthInfoResponseMessage infoResponse =
      SshUserAuthInfoResponseMessage(responses: const <String>['123456']);
  final SshUserAuthInfoResponseMessage decodedInfoResponse =
      SshUserAuthInfoResponseMessage.decodePayload(
    infoResponse.encodePayload(),
  );
  assert(decodedInfoResponse.responses.single == '123456');
}

Future<void> _exerciseHostKeyVerification() async {
  final SshHostKey hostKey = _testHostKey();
  assert(hostKey.algorithm == 'ssh-ed25519');
  assert(hostKey.base64Encoded.isNotEmpty);

  final SshStaticHostKeyVerifier verifier = SshStaticHostKeyVerifier(
    trustedKeys: <SshTrustedHostKey>[
      SshTrustedHostKey(host: 'localhost', hostKey: hostKey),
    ],
  );
  final SshHostKeyVerificationResult success = await verifier.verify(
    SshHostKeyVerificationContext(
      host: 'localhost',
      port: 22,
      localIdentification: 'SSH-2.0-ssh_core-test',
      remoteIdentification: 'SSH-2.0-demo-server',
      hostKey: hostKey,
    ),
  );
  assert(success.isSuccess);

  final SshHostKeyVerificationResult failure = await verifier.verify(
    SshHostKeyVerificationContext(
      host: 'localhost',
      port: 22,
      localIdentification: 'SSH-2.0-ssh_core-test',
      remoteIdentification: 'SSH-2.0-demo-server',
      hostKey: SshHostKey.decode(
        (SshPayloadWriter()
              ..writeString('ssh-ed25519')
              ..writeStringBytes(const <int>[9, 9, 9]))
            .toBytes(),
      ),
    ),
  );
  assert(!failure.isSuccess);
}

Future<void> _exerciseSocketTransport() async {
  final SshPacketCodec codec = SshPacketCodec(
    paddingBytesFactory: (int length) =>
        List<int>.generate(length, (int i) => i + 10),
  );
  final ServerSocket server = await ServerSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
  );

  final Future<void> serverTask = () async {
    final Socket socket = await server.first;
    final StreamIterator<List<int>> iterator =
        StreamIterator<List<int>>(socket);
    final SshTransportBuffer serverBuffer = SshTransportBuffer(
      packetCodec: codec,
    );

    try {
      String? clientBanner;
      while (clientBanner == null) {
        final bool hasNext = await iterator.moveNext();
        assert(hasNext);
        serverBuffer.add(iterator.current);
        clientBanner = serverBuffer.readLine();
      }

      assert(clientBanner == 'SSH-2.0-ssh_core-socket-test');

      socket.add(
        utf8.encode('server prelude\r\nSSH-2.0-ssh_core-test-server\r\n'),
      );
      await socket.flush();

      SshBinaryPacket? packet;
      while (packet == null) {
        final bool hasNext = await iterator.moveNext();
        assert(hasNext);
        serverBuffer.add(iterator.current);
        packet = serverBuffer.readPacket();
      }

      assert(utf8.decode(packet.payload) == 'ping');

      socket.add(codec.encode(utf8.encode('pong')));
      await socket.flush();
      await socket.close();
      socket.destroy();
    } finally {
      await iterator.cancel();
    }
  }();

  final SshSocketTransport transport = SshSocketTransport(
    packetCodec: codec,
  );
  final SshPacketTransport packetTransport = transport;
  final SshHandshakeInfo handshake = await transport.connect(
    endpoint: SshEndpoint(
        host: InternetAddress.loopbackIPv4.address, port: server.port),
    settings: const SshTransportSettings(
      clientIdentification: 'SSH-2.0-ssh_core-socket-test',
    ),
  );

  assert(handshake.remoteIdentification == 'SSH-2.0-ssh_core-test-server');

  await packetTransport.writePacket(utf8.encode('ping'));
  final SshBinaryPacket reply = await packetTransport.readPacket();
  assert(utf8.decode(reply.payload) == 'pong');

  await transport.disconnect();
  await serverTask;
  await server.close();
}

class _FakeTransport implements SshTransport {
  _FakeTransport({required SshHostKey hostKey}) : _hostKey = hostKey;

  SshTransportState _state = SshTransportState.disconnected;
  final SshBannerExchange _bannerExchange = const SshBannerExchange();
  final SshHostKey _hostKey;

  @override
  SshTransportState get state => _state;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    _state = SshTransportState.connected;
    final SshTransportStream transportStream = SshTransportStream(
      incoming: Stream<List<int>>.fromIterable(<List<int>>[
        utf8.encode('fake daemon boot message\r\nSSH-2.0-fake\r\n'),
      ]),
      onWrite: (List<int> bytes) {},
      bannerExchange: _bannerExchange,
    );

    final SshBannerExchangeResult exchange =
        await transportStream.exchangeBanners(
      localIdentification: settings.clientIdentification,
    );

    return SshHandshakeInfo.fromBannerExchange(
      exchange,
      hostKey: _hostKey,
      negotiatedAlgorithms: const <String, String>{'kex': 'curve25519-sha256'},
    );
  }

  @override
  Future<void> disconnect() async {
    _state = SshTransportState.closed;
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}
}

bool _sameBytes(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }

  for (int index = 0; index < left.length; index += 1) {
    if (left[index] != right[index]) {
      return false;
    }
  }

  return true;
}

SshHostKey _testHostKey() {
  final SshPayloadWriter writer = SshPayloadWriter()
    ..writeString('ssh-ed25519')
    ..writeStringBytes(const <int>[1, 2, 3, 4, 5, 6]);
  return SshHostKey.decode(writer.toBytes());
}

class _FakeAuthenticator implements SshAuthenticator {
  @override
  Future<SshAuthResult> authenticate({
    required SshAuthContext context,
    required List<SshAuthMethod> methods,
  }) async {
    return methods.isEmpty
        ? const SshAuthResult.failure(message: 'Missing auth methods.')
        : const SshAuthResult.success();
  }
}

class _FakeChannel implements SshChannel {
  @override
  int get id => 1;

  @override
  SshChannelType get type => SshChannelType.session;

  @override
  Future<void> close() async {}

  @override
  Future<void> sendRequest(SshChannelRequest request) async {}
}

class _FakeChannelFactory implements SshChannelFactory {
  @override
  Future<SshChannel> openChannel(SshChannelOpenRequest request) async {
    return _FakeChannel();
  }
}

class _FakeShellSession implements SshShellSession {
  _FakeShellSession(this.channel);

  @override
  final SshChannel channel;

  @override
  SshSessionState get state => SshSessionState.active;

  @override
  Stream<List<int>> get stderr => const Stream<List<int>>.empty();

  @override
  Stream<List<int>> get stdout => const Stream<List<int>>.empty();

  @override
  Future<void> close() async {}

  @override
  Future<void> resizePty(SshPtyConfig nextPty) async {}

  @override
  Future<void> writeStdin(List<int> data) async {}
}

class _FakeSessionManager implements SshSessionManager {
  @override
  Future<SshShellSession> openShellSession(SshShellRequest request) async {
    return _FakeShellSession(_FakeChannel());
  }
}

class _FakeExecService implements SshExecService {
  @override
  Future<SshExecResult> exec(SshExecRequest request) async {
    return SshExecResult(
      exitCode: 0,
      stdout: utf8.encode('ok:${request.command}\n'),
    );
  }
}

class _FakeSftpClient implements SftpClient {
  @override
  Future<void> close() async {}

  @override
  Future<void> createDirectory(String path, {bool recursive = false}) async {}

  @override
  Future<void> delete(String path, {bool recursive = false}) async {}

  @override
  Future<List<SftpFileEntry>> listDirectory(String path) async {
    return const <SftpFileEntry>[
      SftpFileEntry(path: '/tmp/demo.txt', type: SftpFileType.file),
    ];
  }

  @override
  Future<List<int>> readFile(String path) async {
    return utf8.encode('demo');
  }

  @override
  Future<void> writeFile(String path, List<int> bytes) async {}
}

class _FakeSftpSubsystem implements SftpSubsystem {
  @override
  Future<SftpClient> open() async {
    return _FakeSftpClient();
  }
}

class _FakePortForward implements SshPortForward {
  const _FakePortForward({
    required this.mode,
    required this.bindHost,
    required this.bindPort,
  });

  @override
  final SshForwardingMode mode;

  @override
  final String bindHost;

  @override
  final int bindPort;

  @override
  Future<void> close() async {}
}

class _FakePortForwardingService implements SshPortForwardingService {
  @override
  Future<SshPortForward> openForward(SshForwardRequest request) async {
    return _FakePortForward(
      mode: request.mode,
      bindHost: request.bindHost,
      bindPort: request.bindPort,
    );
  }
}
