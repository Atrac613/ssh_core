import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssh_core/ssh_core_io.dart';

Future<void> main() async {
  await _exerciseTransportPrimitives();
  await _exerciseGlobalRequestProtocol();
  await _exerciseAuthProtocol();
  await _exerciseProtocolAuthenticator();
  await _exerciseChannelProtocol();
  await _exercisePacketChannels();
  await _exerciseSessionProtocol();
  await _exerciseSftpProtocol();
  await _exerciseForwardingProtocol();
  await _exerciseSocks5Protocol();
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

  final SshUserAuthRequestMessage publicKeyRequest =
      SshUserAuthRequestMessage.publicKey(
    username: 'tester',
    algorithm: 'ssh-ed25519',
    publicKey: const <int>[1, 2, 3, 4],
    signature: SshSignature(
      algorithm: 'ssh-ed25519',
      blob: const <int>[9, 8, 7],
    ).encode(),
  );
  final SshUserAuthRequestMessage decodedPublicKeyRequest =
      SshUserAuthRequestMessage.decodePayload(publicKeyRequest.encodePayload());
  assert(decodedPublicKeyRequest.methodName == 'publickey');
  final SshPayloadReader publicKeyReader = SshPayloadReader(
    decodedPublicKeyRequest.methodPayload,
  );
  final bool includesSignature = publicKeyReader.readBool();
  final String publicKeyAlgorithm = publicKeyReader.readString();
  final Uint8List publicKeyBytes = publicKeyReader.readStringBytes();
  final SshSignature publicKeySignature = SshSignature.decode(
    publicKeyReader.readStringBytes(),
  );
  assert(includesSignature);
  assert(publicKeyAlgorithm == 'ssh-ed25519');
  assert(_sameBytes(publicKeyBytes, const <int>[1, 2, 3, 4]));
  assert(publicKeySignature.algorithm == 'ssh-ed25519');
  assert(_sameBytes(publicKeySignature.blob, const <int>[9, 8, 7]));
  publicKeyReader.expectDone();

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

Future<void> _exerciseGlobalRequestProtocol() async {
  final SshGlobalRequestMessage globalRequest = SshGlobalRequestMessage(
    requestName: 'tcpip-forward',
    wantReply: true,
    requestData: (SshPayloadWriter()
          ..writeString('127.0.0.1')
          ..writeUint32(8080))
        .toBytes(),
  );
  final SshGlobalRequestMessage decodedGlobalRequest =
      SshGlobalRequestMessage.decodePayload(globalRequest.encodePayload());
  assert(decodedGlobalRequest.requestName == 'tcpip-forward');
  assert(decodedGlobalRequest.wantReply);
  final SshPayloadReader requestDataReader = SshPayloadReader(
    decodedGlobalRequest.requestData,
  );
  final String requestedHost = requestDataReader.readString();
  final int requestedPort = requestDataReader.readUint32();
  assert(requestedHost == '127.0.0.1');
  assert(requestedPort == 8080);
  requestDataReader.expectDone();

  final SshRequestSuccessMessage success = SshRequestSuccessMessage(
    responseData: (SshPayloadWriter()..writeUint32(49152)).toBytes(),
  );
  final SshRequestSuccessMessage decodedSuccess =
      SshRequestSuccessMessage.decodePayload(success.encodePayload());
  final SshPayloadReader successReader = SshPayloadReader(
    decodedSuccess.responseData,
  );
  final int boundPort = successReader.readUint32();
  assert(boundPort == 49152);
  successReader.expectDone();

  final SshRequestFailureMessage failure = const SshRequestFailureMessage();
  final SshRequestFailureMessage decodedFailure =
      SshRequestFailureMessage.decodePayload(failure.encodePayload());
  assert(decodedFailure.encodePayload().single ==
      SshMessageId.requestFailure.value);
}

Future<void> _exerciseProtocolAuthenticator() async {
  final SshUserAuthProtocolAuthenticator authenticator =
      const SshUserAuthProtocolAuthenticator();
  final _ScriptedPacketTransport passwordTransport = _ScriptedPacketTransport(
    scriptedPackets: <List<int>>[
      SshServiceAcceptMessage(serviceName: sshUserauthService).encodePayload(),
      SshUserAuthFailureMessage(
        allowedMethods: const <String>['password'],
      ).encodePayload(),
      const SshUserAuthSuccessMessage().encodePayload(),
    ],
  );
  final SshAuthResult passwordResult = await authenticator.authenticate(
    context: SshAuthContext(
      config: const SshClientConfig(host: 'localhost', username: 'tester'),
      transport: passwordTransport,
      handshake: const SshHandshakeInfo(
        localIdentification: 'SSH-2.0-ssh_core-test',
        remoteIdentification: 'SSH-2.0-demo-server',
      ),
    ),
    methods: const <SshAuthMethod>[
      SshNoneAuthMethod(),
      SshPasswordAuthMethod(password: 'pw'),
    ],
  );
  assert(passwordResult.isSuccess);
  assert(passwordTransport.writtenPayloads.length == 3);
  final SshServiceRequestMessage authServiceRequest =
      SshServiceRequestMessage.decodePayload(
          passwordTransport.writtenPayloads[0]);
  assert(authServiceRequest.serviceName == sshUserauthService);
  final SshUserAuthRequestMessage noneRequest =
      SshUserAuthRequestMessage.decodePayload(
          passwordTransport.writtenPayloads[1]);
  assert(noneRequest.methodName == 'none');
  final SshUserAuthRequestMessage passwordRequest =
      SshUserAuthRequestMessage.decodePayload(
          passwordTransport.writtenPayloads[2]);
  assert(passwordRequest.methodName == 'password');

  final _ScriptedPacketTransport keyboardInteractiveTransport =
      _ScriptedPacketTransport(
    scriptedPackets: <List<int>>[
      SshServiceAcceptMessage(serviceName: sshUserauthService).encodePayload(),
      SshUserAuthInfoRequestMessage(
        prompts: const <SshKeyboardInteractivePrompt>[
          SshKeyboardInteractivePrompt(prompt: 'Code: ', echo: false),
        ],
      ).encodePayload(),
      const SshUserAuthSuccessMessage().encodePayload(),
    ],
  );
  final SshAuthResult keyboardInteractiveResult =
      await authenticator.authenticate(
    context: SshAuthContext(
      config: const SshClientConfig(host: 'localhost', username: 'tester'),
      transport: keyboardInteractiveTransport,
      handshake: const SshHandshakeInfo(
        localIdentification: 'SSH-2.0-ssh_core-test',
        remoteIdentification: 'SSH-2.0-demo-server',
      ),
    ),
    methods: <SshAuthMethod>[
      SshKeyboardInteractiveAuthMethod(
        respond: (List<SshKeyboardInteractivePrompt> prompts) async {
          assert(prompts.single.prompt == 'Code: ');
          return const <String>['123456'];
        },
      ),
    ],
  );
  assert(keyboardInteractiveResult.isSuccess);
  assert(keyboardInteractiveTransport.writtenPayloads.length == 3);
  final SshUserAuthRequestMessage keyboardInteractiveRequest =
      SshUserAuthRequestMessage.decodePayload(
    keyboardInteractiveTransport.writtenPayloads[1],
  );
  assert(keyboardInteractiveRequest.methodName == 'keyboard-interactive');
  final SshUserAuthInfoResponseMessage infoResponse =
      SshUserAuthInfoResponseMessage.decodePayload(
    keyboardInteractiveTransport.writtenPayloads[2],
  );
  assert(infoResponse.responses.single == '123456');

  List<int>? publicKeyChallenge;
  final _ScriptedPacketTransport publicKeyTransport = _ScriptedPacketTransport(
    scriptedPackets: <List<int>>[
      SshServiceAcceptMessage(serviceName: sshUserauthService).encodePayload(),
      SshUserAuthPkOkMessage(
        algorithm: 'ssh-ed25519',
        publicKey: const <int>[1, 2, 3, 4],
      ).encodePayload(),
      const SshUserAuthSuccessMessage().encodePayload(),
    ],
  );
  final SshAuthResult publicKeyResult = await authenticator.authenticate(
    context: SshAuthContext(
      config: const SshClientConfig(host: 'localhost', username: 'tester'),
      transport: publicKeyTransport,
      handshake: const SshHandshakeInfo(
        localIdentification: 'SSH-2.0-ssh_core-test',
        remoteIdentification: 'SSH-2.0-demo-server',
        sessionIdentifier: <int>[1, 3, 3, 7],
      ),
    ),
    methods: <SshAuthMethod>[
      SshPublicKeyAuthMethod(
        algorithm: 'ssh-ed25519',
        publicKey: const <int>[1, 2, 3, 4],
        sign: (List<int> challenge) async {
          publicKeyChallenge = List<int>.from(challenge);
          return const <int>[4, 3, 2, 1];
        },
      ),
    ],
  );
  assert(publicKeyResult.isSuccess);
  assert(publicKeyTransport.writtenPayloads.length == 3);
  final SshUserAuthRequestMessage unsignedPublicKeyRequest =
      SshUserAuthRequestMessage.decodePayload(
    publicKeyTransport.writtenPayloads[1],
  );
  final SshPayloadReader unsignedPublicKeyReader = SshPayloadReader(
    unsignedPublicKeyRequest.methodPayload,
  );
  final bool unsignedHasSignature = unsignedPublicKeyReader.readBool();
  final String unsignedAlgorithm = unsignedPublicKeyReader.readString();
  final Uint8List unsignedPublicKey = unsignedPublicKeyReader.readStringBytes();
  assert(unsignedHasSignature == false);
  assert(unsignedAlgorithm == 'ssh-ed25519');
  assert(_sameBytes(unsignedPublicKey, const <int>[1, 2, 3, 4]));
  unsignedPublicKeyReader.expectDone();

  final SshUserAuthRequestMessage signedPublicKeyRequest =
      SshUserAuthRequestMessage.decodePayload(
    publicKeyTransport.writtenPayloads[2],
  );
  final SshPayloadReader signedPublicKeyReader = SshPayloadReader(
    signedPublicKeyRequest.methodPayload,
  );
  final bool signedHasSignature = signedPublicKeyReader.readBool();
  final String signedAlgorithm = signedPublicKeyReader.readString();
  final Uint8List signedPublicKey = signedPublicKeyReader.readStringBytes();
  final SshSignature signedSignature = SshSignature.decode(
    signedPublicKeyReader.readStringBytes(),
  );
  assert(signedHasSignature);
  assert(signedAlgorithm == 'ssh-ed25519');
  assert(_sameBytes(signedPublicKey, const <int>[1, 2, 3, 4]));
  assert(signedSignature.algorithm == 'ssh-ed25519');
  assert(_sameBytes(signedSignature.blob, const <int>[4, 3, 2, 1]));
  signedPublicKeyReader.expectDone();

  final Uint8List expectedPublicKeyChallenge = (SshPayloadWriter()
        ..writeStringBytes(const <int>[1, 3, 3, 7])
        ..writeByte(SshMessageId.userauthRequest.value)
        ..writeString('tester')
        ..writeString(sshConnectionService)
        ..writeString('publickey')
        ..writeBool(true)
        ..writeString('ssh-ed25519')
        ..writeStringBytes(const <int>[1, 2, 3, 4]))
      .toBytes();
  assert(
    _sameBytes(publicKeyChallenge ?? const <int>[], expectedPublicKeyChallenge),
  );
}

Future<void> _exerciseChannelProtocol() async {
  final SshChannelOpenMessage open = SshChannelOpenMessage(
    channelType: 'session',
    senderChannel: 1,
    initialWindowSize: 1024,
    maximumPacketSize: 32768,
  );
  final SshChannelOpenMessage decodedOpen = SshChannelOpenMessage.decodePayload(
    open.encodePayload(),
  );
  assert(decodedOpen.channelType == 'session');
  assert(decodedOpen.senderChannel == 1);

  final SshChannelOpenConfirmationMessage confirmation =
      SshChannelOpenConfirmationMessage(
    recipientChannel: 1,
    senderChannel: 7,
    initialWindowSize: 2048,
    maximumPacketSize: 32768,
  );
  final SshChannelOpenConfirmationMessage decodedConfirmation =
      SshChannelOpenConfirmationMessage.decodePayload(
    confirmation.encodePayload(),
  );
  assert(decodedConfirmation.recipientChannel == 1);
  assert(decodedConfirmation.senderChannel == 7);

  final SshChannelOpenFailureMessage failure = SshChannelOpenFailureMessage(
    recipientChannel: 1,
    reason: SshChannelOpenFailureReason.connectFailed,
    description: 'Connection refused',
  );
  final SshChannelOpenFailureMessage decodedFailure =
      SshChannelOpenFailureMessage.decodePayload(failure.encodePayload());
  assert(
    decodedFailure.reason == SshChannelOpenFailureReason.connectFailed,
  );
  assert(decodedFailure.description == 'Connection refused');

  final SshChannelWindowAdjustMessage windowAdjust =
      const SshChannelWindowAdjustMessage(
    recipientChannel: 1,
    bytesToAdd: 4096,
  );
  final SshChannelWindowAdjustMessage decodedWindowAdjust =
      SshChannelWindowAdjustMessage.decodePayload(windowAdjust.encodePayload());
  assert(decodedWindowAdjust.bytesToAdd == 4096);

  final SshChannelDataMessage data = SshChannelDataMessage(
    recipientChannel: 1,
    data: utf8.encode('hello'),
  );
  final SshChannelDataMessage decodedData = SshChannelDataMessage.decodePayload(
    data.encodePayload(),
  );
  assert(utf8.decode(decodedData.data) == 'hello');

  final SshChannelExtendedDataMessage extendedData =
      SshChannelExtendedDataMessage(
    recipientChannel: 1,
    dataTypeCode: 1,
    data: utf8.encode('stderr'),
  );
  final SshChannelExtendedDataMessage decodedExtendedData =
      SshChannelExtendedDataMessage.decodePayload(extendedData.encodePayload());
  assert(decodedExtendedData.dataTypeCode == 1);
  assert(utf8.decode(decodedExtendedData.data) == 'stderr');

  final SshChannelRequestMessage request = SshChannelRequestMessage(
    recipientChannel: 1,
    requestType: 'shell',
    wantReply: true,
  );
  final SshChannelRequestMessage decodedRequest =
      SshChannelRequestMessage.decodePayload(request.encodePayload());
  assert(decodedRequest.requestType == 'shell');
  assert(decodedRequest.wantReply);

  final SshChannelSuccessMessage success = const SshChannelSuccessMessage(
    recipientChannel: 1,
  );
  final SshChannelSuccessMessage decodedSuccess =
      SshChannelSuccessMessage.decodePayload(success.encodePayload());
  assert(decodedSuccess.recipientChannel == 1);

  final SshChannelFailureMessage requestFailure =
      const SshChannelFailureMessage(
    recipientChannel: 1,
  );
  final SshChannelFailureMessage decodedRequestFailure =
      SshChannelFailureMessage.decodePayload(requestFailure.encodePayload());
  assert(decodedRequestFailure.recipientChannel == 1);

  final SshChannelEofMessage eof = const SshChannelEofMessage(
    recipientChannel: 1,
  );
  final SshChannelEofMessage decodedEof = SshChannelEofMessage.decodePayload(
    eof.encodePayload(),
  );
  assert(decodedEof.recipientChannel == 1);

  final SshChannelCloseMessage close = const SshChannelCloseMessage(
    recipientChannel: 1,
  );
  final SshChannelCloseMessage decodedClose =
      SshChannelCloseMessage.decodePayload(close.encodePayload());
  assert(decodedClose.recipientChannel == 1);
}

Future<void> _exercisePacketChannels() async {
  final _ScriptedPacketTransport transport = _ScriptedPacketTransport(
    scriptedPackets: <List<int>>[
      SshChannelOpenConfirmationMessage(
        recipientChannel: 0,
        senderChannel: 41,
        initialWindowSize: 65536,
        maximumPacketSize: 32768,
      ).encodePayload(),
      const SshChannelSuccessMessage(recipientChannel: 0).encodePayload(),
      SshChannelDataMessage(
        recipientChannel: 0,
        data: utf8.encode('hello'),
      ).encodePayload(),
      SshChannelExtendedDataMessage(
        recipientChannel: 0,
        dataTypeCode: 1,
        data: utf8.encode('warn'),
      ).encodePayload(),
      SshChannelRequestMessage(
        recipientChannel: 0,
        requestType: 'exit-status',
        requestData: const SshExitStatusChannelRequest(exitStatus: 23).encode(),
      ).encodePayload(),
      const SshChannelEofMessage(recipientChannel: 0).encodePayload(),
      const SshChannelCloseMessage(recipientChannel: 0).encodePayload(),
    ],
  );
  final SshPacketChannelFactory factory = SshPacketChannelFactory(
    transport: transport,
  );
  final SshPacketChannel channel = await factory.openSessionChannel();
  assert(channel.id == 0);
  assert(channel.type == SshChannelType.session);

  await channel.sendRequest(
    SshChannelRequest(
      type: 'exec',
      wantReply: true,
      payload: <String, Object?>{
        'encodedPayload': const SshExecChannelRequest(command: 'true').encode(),
      },
    ),
  );

  final List<int> stdoutData = await channel.stdout.first;
  final List<int> stderrData = await channel.stderr.first;
  final SshChannelRequestMessage inboundRequest =
      await channel.inboundRequests.first;
  await channel.done;

  assert(utf8.decode(stdoutData) == 'hello');
  assert(utf8.decode(stderrData) == 'warn');
  assert(inboundRequest.requestType == 'exit-status');
  final SshExitStatusChannelRequest exitStatus =
      SshExitStatusChannelRequest.decode(inboundRequest.requestData);
  assert(exitStatus.exitStatus == 23);

  assert(transport.writtenPayloads.length == 3);
  final SshChannelOpenMessage openMessage = SshChannelOpenMessage.decodePayload(
    transport.writtenPayloads[0],
  );
  assert(openMessage.channelType == 'session');
  final SshChannelRequestMessage requestMessage =
      SshChannelRequestMessage.decodePayload(transport.writtenPayloads[1]);
  assert(requestMessage.requestType == 'exec');
  final SshChannelCloseMessage closeMessage =
      SshChannelCloseMessage.decodePayload(transport.writtenPayloads[2]);
  assert(closeMessage.recipientChannel == 41);
}

Future<void> _exerciseSessionProtocol() async {
  final SshEnvChannelRequest env = const SshEnvChannelRequest(
    name: 'LANG',
    value: 'en_US.UTF-8',
  );
  final SshEnvChannelRequest decodedEnv = SshEnvChannelRequest.decode(
    env.encode(),
  );
  assert(decodedEnv.name == 'LANG');
  assert(decodedEnv.value == 'en_US.UTF-8');
  assert(env.toChannelRequestMessage(1).requestType == 'env');

  final SshPtyConfig pty = const SshPtyConfig(
    terminalType: 'xterm-256color',
    columns: 120,
    rows: 40,
    modes: <SshPtyMode, int>{
      SshPtyMode.echo: 1,
      SshPtyMode.signals: 1,
    },
  );
  final SshPtyChannelRequest ptyRequest = SshPtyChannelRequest(pty: pty);
  final SshPtyChannelRequest decodedPtyRequest = SshPtyChannelRequest.decode(
    ptyRequest.encode(),
  );
  assert(decodedPtyRequest.pty.columns == 120);
  assert(decodedPtyRequest.pty.rows == 40);
  assert(decodedPtyRequest.pty.modes[SshPtyMode.echo] == 1);
  assert(ptyRequest.toChannelRequestMessage(1).requestType == 'pty-req');

  final SshWindowChangeChannelRequest windowChange =
      const SshWindowChangeChannelRequest(
    columns: 140,
    rows: 50,
  );
  final SshWindowChangeChannelRequest decodedWindowChange =
      SshWindowChangeChannelRequest.decode(windowChange.encode());
  assert(decodedWindowChange.columns == 140);
  assert(
      windowChange.toChannelRequestMessage(1).requestType == 'window-change');

  final SshShellChannelRequest shell = const SshShellChannelRequest();
  final SshShellChannelRequest decodedShell = SshShellChannelRequest.decode(
    shell.encode(),
  );
  assert(decodedShell.toChannelRequestMessage(1).requestType == 'shell');

  final SshExecChannelRequest exec = const SshExecChannelRequest(
    command: 'uname -a',
  );
  final SshExecChannelRequest decodedExec = SshExecChannelRequest.decode(
    exec.encode(),
  );
  assert(decodedExec.command == 'uname -a');
  assert(exec.toChannelRequestMessage(1).requestType == 'exec');

  final SshSubsystemChannelRequest subsystem =
      const SshSubsystemChannelRequest(subsystem: 'sftp');
  final SshSubsystemChannelRequest decodedSubsystem =
      SshSubsystemChannelRequest.decode(subsystem.encode());
  assert(decodedSubsystem.subsystem == 'sftp');

  final SshExitStatusChannelRequest exitStatus =
      const SshExitStatusChannelRequest(exitStatus: 23);
  final SshExitStatusChannelRequest decodedExitStatus =
      SshExitStatusChannelRequest.decode(exitStatus.encode());
  assert(decodedExitStatus.exitStatus == 23);

  final SshExitSignalChannelRequest exitSignal =
      const SshExitSignalChannelRequest(
    signalName: 'TERM',
    coreDumped: false,
    errorMessage: 'Terminated.',
  );
  final SshExitSignalChannelRequest decodedExitSignal =
      SshExitSignalChannelRequest.decode(exitSignal.encode());
  assert(decodedExitSignal.signalName == 'TERM');
  assert(decodedExitSignal.errorMessage == 'Terminated.');
}

Future<void> _exerciseSftpProtocol() async {
  final SftpPacketCodec packetCodec = const SftpPacketCodec();

  final SftpPacket decodedInitPacket = packetCodec.decode(
    packetCodec.encode(const SftpInitMessage(version: 3).toPacket()),
  );
  assert(decodedInitPacket.type == SftpPacketType.init);
  assert(decodedInitPacket.requestId == null);
  final SftpInitMessage decodedInit = SftpInitMessage.decodePayload(
    decodedInitPacket.payload,
  );
  assert(decodedInit.version == 3);

  final SftpVersionMessage versionMessage = SftpVersionMessage(
    version: 3,
    extensions: const <String, String>{'posix-rename@openssh.com': '1'},
  );
  final SftpPacket decodedVersionPacket = packetCodec.decode(
    packetCodec.encode(versionMessage.toPacket()),
  );
  assert(decodedVersionPacket.type == SftpPacketType.version);
  assert(decodedVersionPacket.requestId == null);
  final SftpVersionMessage decodedVersion = SftpVersionMessage.decodePayload(
    decodedVersionPacket.payload,
  );
  assert(decodedVersion.extensions['posix-rename@openssh.com'] == '1');

  final SftpFileAttributes attributes = SftpFileAttributes(
    size: 4294967297,
    userId: 1000,
    groupId: 1000,
    permissions: 0x1A4,
    accessTime: 1700000000,
    modifiedTime: 1700000123,
    extensions: const <String, List<int>>{
      'vendor@example.com': <int>[7, 8, 9],
    },
  );
  final SftpFileAttributes decodedAttributes = SftpFileAttributes.decode(
    SshPayloadReader(attributes.encode()),
  );
  assert(decodedAttributes.size == 4294967297);
  assert(decodedAttributes.userId == 1000);
  assert(decodedAttributes.groupId == 1000);
  assert(decodedAttributes.permissions == 0x1A4);
  assert(decodedAttributes.accessTime == 1700000000);
  assert(decodedAttributes.modifiedTime == 1700000123);
  assert(
    _sameBytes(
      decodedAttributes.extensions['vendor@example.com']!,
      const <int>[7, 8, 9],
    ),
  );

  final SftpOpenRequest openRequest = SftpOpenRequest(
    filename: '/tmp/demo.txt',
    pflags: 0x00000001 | 0x00000008,
    attributes: attributes,
  );
  final SftpOpenRequest decodedOpenRequest = SftpOpenRequest.decodePayload(
    openRequest.encodePayload(),
  );
  assert(decodedOpenRequest.filename == '/tmp/demo.txt');
  assert(decodedOpenRequest.pflags == 0x00000009);
  assert(decodedOpenRequest.attributes.permissions == 0x1A4);

  final SftpReadRequest readRequest = SftpReadRequest(
    handle: const <int>[1, 2, 3],
    offset: 4294967297,
    length: 4096,
  );
  final SftpPacket decodedReadPacket = packetCodec.decode(
    packetCodec.encode(
      SftpPacket(
        type: SftpPacketType.read,
        requestId: 7,
        payload: readRequest.encodePayload(),
      ),
    ),
  );
  assert(decodedReadPacket.requestId == 7);
  final SftpReadRequest decodedReadRequest = SftpReadRequest.decodePayload(
    decodedReadPacket.payload,
  );
  assert(decodedReadRequest.offset == 4294967297);
  assert(decodedReadRequest.length == 4096);

  final SftpWriteRequest writeRequest = SftpWriteRequest(
    handle: const <int>[4, 5, 6],
    offset: 4294967298,
    data: const <int>[9, 8, 7, 6],
  );
  final SftpWriteRequest decodedWriteRequest = SftpWriteRequest.decodePayload(
    writeRequest.encodePayload(),
  );
  assert(decodedWriteRequest.offset == 4294967298);
  assert(_sameBytes(decodedWriteRequest.data, const <int>[9, 8, 7, 6]));

  final SftpStatusMessage statusMessage = const SftpStatusMessage(
    code: SftpStatusCode.ok,
    message: 'done',
  );
  final SftpStatusMessage decodedStatus = SftpStatusMessage.decodePayload(
    statusMessage.encodePayload(),
  );
  assert(decodedStatus.code == SftpStatusCode.ok);
  assert(decodedStatus.message == 'done');

  final SftpHandleMessage handleMessage = SftpHandleMessage(
    handle: const <int>[10, 11, 12],
  );
  final SftpHandleMessage decodedHandleMessage =
      SftpHandleMessage.decodePayload(handleMessage.encodePayload());
  assert(_sameBytes(decodedHandleMessage.handle, const <int>[10, 11, 12]));

  final SftpDataMessage dataMessage = SftpDataMessage(
    data: const <int>[21, 22, 23],
  );
  final SftpDataMessage decodedDataMessage = SftpDataMessage.decodePayload(
    dataMessage.encodePayload(),
  );
  assert(_sameBytes(decodedDataMessage.data, const <int>[21, 22, 23]));

  final SftpNameMessage nameMessage = SftpNameMessage(
    entries: <SftpNameEntry>[
      SftpNameEntry(
        filename: 'demo.txt',
        longname: '-rw-r--r-- 1 demo demo 4 Jan 1 00:00 demo.txt',
        attributes: SftpFileAttributes(
          size: 4,
          permissions: 0x1A4,
        ),
      ),
    ],
  );
  final SftpNameMessage decodedNameMessage = SftpNameMessage.decodePayload(
    nameMessage.encodePayload(),
  );
  assert(decodedNameMessage.entries.single.filename == 'demo.txt');
  assert(decodedNameMessage.entries.single.attributes.size == 4);

  final SftpPathRequest mkdirRequest = SftpPathRequest(
    path: '/tmp/new-dir',
    type: SftpPacketType.mkdir,
    attributes: SftpFileAttributes(permissions: 0x1ED),
  );
  final SftpPathRequest decodedMkdirRequest = SftpPathRequest.decodePayload(
    mkdirRequest.encodePayload(),
    SftpPacketType.mkdir,
  );
  assert(decodedMkdirRequest.path == '/tmp/new-dir');
  assert(decodedMkdirRequest.attributes.permissions == 0x1ED);

  final SftpPathRequest removeRequest = const SftpPathRequest(
    path: '/tmp/demo.txt',
    type: SftpPacketType.remove,
  );
  final SftpPathRequest decodedRemoveRequest = SftpPathRequest.decodePayload(
    removeRequest.encodePayload(),
    SftpPacketType.remove,
  );
  assert(decodedRemoveRequest.path == '/tmp/demo.txt');
  assert(decodedRemoveRequest.attributes.isEmpty);

  final SftpHandleRequest readdirRequest = SftpHandleRequest(
    type: SftpPacketType.readdir,
    handle: const <int>[13, 14, 15],
  );
  final SftpHandleRequest decodedHandleRequest =
      SftpHandleRequest.decodePayload(
    readdirRequest.encodePayload(),
    SftpPacketType.readdir,
  );
  assert(decodedHandleRequest.type == SftpPacketType.readdir);
  assert(_sameBytes(decodedHandleRequest.handle, const <int>[13, 14, 15]));
}

Future<void> _exerciseForwardingProtocol() async {
  final SshTcpIpForwardRequest remoteForward = const SshTcpIpForwardRequest(
    bindHost: '0.0.0.0',
    bindPort: 0,
  );
  final SshTcpIpForwardRequest decodedRemoteForward =
      SshTcpIpForwardRequest.decode(remoteForward.encode());
  assert(decodedRemoteForward.bindHost == '0.0.0.0');
  assert(decodedRemoteForward.bindPort == 0);

  final SshGlobalRequestMessage forwardGlobalRequest =
      remoteForward.toGlobalRequest();
  final SshGlobalRequestMessage decodedForwardGlobalRequest =
      SshGlobalRequestMessage.decodePayload(
          forwardGlobalRequest.encodePayload());
  assert(decodedForwardGlobalRequest.requestName == sshTcpIpForwardRequestName);
  assert(decodedForwardGlobalRequest.wantReply);
  final SshTcpIpForwardRequest forwardedPayload =
      SshTcpIpForwardRequest.decode(decodedForwardGlobalRequest.requestData);
  assert(forwardedPayload.bindHost == '0.0.0.0');
  assert(forwardedPayload.bindPort == 0);

  final SshCancelTcpIpForwardRequest cancelForward =
      const SshCancelTcpIpForwardRequest(
    bindHost: '127.0.0.1',
    bindPort: 8022,
  );
  final SshCancelTcpIpForwardRequest decodedCancelForward =
      SshCancelTcpIpForwardRequest.decode(cancelForward.encode());
  assert(decodedCancelForward.bindHost == '127.0.0.1');
  assert(decodedCancelForward.bindPort == 8022);
  final SshGlobalRequestMessage cancelGlobalRequest =
      cancelForward.toGlobalRequest();
  final SshGlobalRequestMessage decodedCancelGlobalRequest =
      SshGlobalRequestMessage.decodePayload(
          cancelGlobalRequest.encodePayload());
  assert(
    decodedCancelGlobalRequest.requestName == sshCancelTcpIpForwardRequestName,
  );

  final SshTcpIpForwardSuccessResponse successResponse =
      const SshTcpIpForwardSuccessResponse(boundPort: 49152);
  final SshTcpIpForwardSuccessResponse decodedSuccessResponse =
      SshTcpIpForwardSuccessResponse.fromSuccessMessage(
    successResponse.toSuccessMessage(),
  );
  assert(decodedSuccessResponse.boundPort == 49152);

  final SshDirectTcpIpChannelOpenData directTcpIp =
      const SshDirectTcpIpChannelOpenData(
    targetHost: 'db.internal',
    targetPort: 5432,
    originatorHost: '127.0.0.1',
    originatorPort: 40000,
  );
  final SshChannelOpenMessage directOpen = directTcpIp.toChannelOpenMessage(
    senderChannel: 7,
    localWindow:
        const SshChannelWindow(initialSize: 65536, maxPacketSize: 8192),
  );
  final SshChannelOpenMessage decodedDirectOpen =
      SshChannelOpenMessage.decodePayload(
    directOpen.encodePayload(),
  );
  assert(decodedDirectOpen.channelType == sshDirectTcpIpChannelType);
  assert(decodedDirectOpen.senderChannel == 7);
  final SshDirectTcpIpChannelOpenData decodedDirectTcpIp =
      SshDirectTcpIpChannelOpenData.fromChannelOpenMessage(decodedDirectOpen);
  assert(decodedDirectTcpIp.targetHost == 'db.internal');
  assert(decodedDirectTcpIp.targetPort == 5432);
  assert(decodedDirectTcpIp.originatorHost == '127.0.0.1');
  assert(decodedDirectTcpIp.originatorPort == 40000);

  final SshForwardedTcpIpChannelOpenData forwardedTcpIp =
      const SshForwardedTcpIpChannelOpenData(
    connectedHost: '127.0.0.1',
    connectedPort: 2222,
    originatorHost: '203.0.113.10',
    originatorPort: 50000,
  );
  final SshChannelOpenMessage forwardedOpen =
      forwardedTcpIp.toChannelOpenMessage(senderChannel: 11);
  final SshChannelOpenMessage decodedForwardedOpen =
      SshChannelOpenMessage.decodePayload(forwardedOpen.encodePayload());
  assert(decodedForwardedOpen.channelType == sshForwardedTcpIpChannelType);
  final SshForwardedTcpIpChannelOpenData decodedForwardedTcpIp =
      SshForwardedTcpIpChannelOpenData.fromChannelOpenMessage(
    decodedForwardedOpen,
  );
  assert(decodedForwardedTcpIp.connectedHost == '127.0.0.1');
  assert(decodedForwardedTcpIp.connectedPort == 2222);
  assert(decodedForwardedTcpIp.originatorHost == '203.0.113.10');
  assert(decodedForwardedTcpIp.originatorPort == 50000);
}

Future<void> _exerciseSocks5Protocol() async {
  final SshSocks5Greeting greeting = SshSocks5Greeting(
    methods: const <SshSocks5AuthMethod>[
      SshSocks5AuthMethod.noAuth,
      SshSocks5AuthMethod.usernamePassword,
    ],
  );
  final SshSocks5Greeting decodedGreeting = SshSocks5Greeting.decode(
    greeting.encode(),
  );
  assert(decodedGreeting.methods.length == 2);
  assert(decodedGreeting.methods.first == SshSocks5AuthMethod.noAuth);
  assert(
    decodedGreeting.methods.last == SshSocks5AuthMethod.usernamePassword,
  );

  final SshSocks5MethodSelection methodSelection =
      const SshSocks5MethodSelection(method: SshSocks5AuthMethod.noAuth);
  final SshSocks5MethodSelection decodedMethodSelection =
      SshSocks5MethodSelection.decode(methodSelection.encode());
  assert(decodedMethodSelection.method == SshSocks5AuthMethod.noAuth);

  final SshSocks5Request connectRequest = SshSocks5Request(
    command: SshSocks5Command.connect,
    destinationAddress: SshSocks5Address.domain('db.internal'),
    destinationPort: 5432,
  );
  final SshSocks5Request decodedConnectRequest = SshSocks5Request.decode(
    connectRequest.encode(),
  );
  assert(decodedConnectRequest.command == SshSocks5Command.connect);
  assert(decodedConnectRequest.destinationAddress.host == 'db.internal');
  assert(decodedConnectRequest.destinationPort == 5432);

  final SshSocks5Reply reply = SshSocks5Reply(
    replyCode: SshSocks5ReplyCode.succeeded,
    boundAddress: SshSocks5Address.ipv4('127.0.0.1'),
    boundPort: 1080,
  );
  final SshSocks5Reply decodedReply = SshSocks5Reply.decode(reply.encode());
  assert(decodedReply.replyCode == SshSocks5ReplyCode.succeeded);
  assert(decodedReply.boundAddress.host == '127.0.0.1');
  assert(decodedReply.boundPort == 1080);

  final SshSocks5Address ipv6Address = SshSocks5Address.ipv6Bytes(
    addressBytes: const <int>[
      0x20,
      0x01,
      0x0D,
      0xB8,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
    ],
  );
  final SshSocks5Reply decodedIpv6Reply = SshSocks5Reply.decode(
    SshSocks5Reply(
      replyCode: SshSocks5ReplyCode.hostUnreachable,
      boundAddress: ipv6Address,
      boundPort: 0,
    ).encode(),
  );
  assert(decodedIpv6Reply.boundAddress.type == SshSocks5AddressType.ipv6);
  assert(decodedIpv6Reply.boundAddress.addressBytes.length == 16);
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

class _ScriptedPacketTransport implements SshPacketTransport {
  _ScriptedPacketTransport({required List<List<int>> scriptedPackets})
      : _scriptedPackets = List<List<int>>.from(scriptedPackets);

  final List<List<int>> _scriptedPackets;
  final List<List<int>> writtenPayloads = <List<int>>[];

  @override
  SshTransportState get state => SshTransportState.connected;

  @override
  Future<SshHandshakeInfo> connect({
    required SshEndpoint endpoint,
    required SshTransportSettings settings,
  }) async {
    return const SshHandshakeInfo(
      localIdentification: 'SSH-2.0-ssh_core-test',
      remoteIdentification: 'SSH-2.0-scripted-server',
    );
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<SshBinaryPacket> readPacket() async {
    if (_scriptedPackets.isEmpty) {
      throw StateError('No scripted SSH packet remains.');
    }

    return SshBinaryPacket(
        payload: _scriptedPackets.removeAt(0),
        padding: const <int>[0, 0, 0, 0]);
  }

  @override
  Future<void> sendGlobalRequest(SshGlobalRequest request) async {}

  @override
  Future<void> writeBytes(List<int> bytes) async {
    writtenPayloads.add(List<int>.from(bytes));
  }

  @override
  Future<void> writePacket(List<int> payload) async {
    writtenPayloads.add(List<int>.from(payload));
  }
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
