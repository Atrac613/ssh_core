import 'message_codec.dart';

class SshAlgorithmNegotiationException implements Exception {
  const SshAlgorithmNegotiationException({
    required this.category,
    required this.clientAlgorithms,
    required this.serverAlgorithms,
  });

  final String category;
  final List<String> clientAlgorithms;
  final List<String> serverAlgorithms;

  @override
  String toString() {
    return 'SshAlgorithmNegotiationException('
        'category: $category, '
        'clientAlgorithms: $clientAlgorithms, '
        'serverAlgorithms: $serverAlgorithms'
        ')';
  }
}

class SshNegotiatedAlgorithms {
  const SshNegotiatedAlgorithms({
    required this.keyExchange,
    required this.serverHostKey,
    required this.encryptionClientToServer,
    required this.encryptionServerToClient,
    required this.macClientToServer,
    required this.macServerToClient,
    required this.compressionClientToServer,
    required this.compressionServerToClient,
    this.languageClientToServer,
    this.languageServerToClient,
    this.ignoreGuessedClientPacket = false,
    this.ignoreGuessedServerPacket = false,
  });

  final String keyExchange;
  final String serverHostKey;
  final String encryptionClientToServer;
  final String encryptionServerToClient;
  final String macClientToServer;
  final String macServerToClient;
  final String compressionClientToServer;
  final String compressionServerToClient;
  final String? languageClientToServer;
  final String? languageServerToClient;
  final bool ignoreGuessedClientPacket;
  final bool ignoreGuessedServerPacket;

  Map<String, String> asHandshakeMap() {
    final Map<String, String> result = <String, String>{
      'kex': keyExchange,
      'serverHostKey': serverHostKey,
      'cipher.clientToServer': encryptionClientToServer,
      'cipher.serverToClient': encryptionServerToClient,
      'mac.clientToServer': macClientToServer,
      'mac.serverToClient': macServerToClient,
      'compression.clientToServer': compressionClientToServer,
      'compression.serverToClient': compressionServerToClient,
    };

    final String? negotiatedLanguageClientToServer = languageClientToServer;
    if (negotiatedLanguageClientToServer != null) {
      result['language.clientToServer'] = negotiatedLanguageClientToServer;
    }

    final String? negotiatedLanguageServerToClient = languageServerToClient;
    if (negotiatedLanguageServerToClient != null) {
      result['language.serverToClient'] = negotiatedLanguageServerToClient;
    }

    return result;
  }
}

class SshAlgorithmNegotiator {
  const SshAlgorithmNegotiator();

  SshNegotiatedAlgorithms negotiate({
    required SshKexInitMessage clientProposal,
    required SshKexInitMessage serverProposal,
  }) {
    final String keyExchange = _selectRequired(
      category: 'kex',
      clientAlgorithms: clientProposal.kexAlgorithms,
      serverAlgorithms: serverProposal.kexAlgorithms,
    );
    final String serverHostKey = _selectRequired(
      category: 'server host key',
      clientAlgorithms: clientProposal.serverHostKeyAlgorithms,
      serverAlgorithms: serverProposal.serverHostKeyAlgorithms,
    );

    return SshNegotiatedAlgorithms(
      keyExchange: keyExchange,
      serverHostKey: serverHostKey,
      encryptionClientToServer: _selectRequired(
        category: 'encryption client->server',
        clientAlgorithms: clientProposal.encryptionAlgorithmsClientToServer,
        serverAlgorithms: serverProposal.encryptionAlgorithmsClientToServer,
      ),
      encryptionServerToClient: _selectRequired(
        category: 'encryption server->client',
        clientAlgorithms: clientProposal.encryptionAlgorithmsServerToClient,
        serverAlgorithms: serverProposal.encryptionAlgorithmsServerToClient,
      ),
      macClientToServer: _selectRequired(
        category: 'mac client->server',
        clientAlgorithms: clientProposal.macAlgorithmsClientToServer,
        serverAlgorithms: serverProposal.macAlgorithmsClientToServer,
      ),
      macServerToClient: _selectRequired(
        category: 'mac server->client',
        clientAlgorithms: clientProposal.macAlgorithmsServerToClient,
        serverAlgorithms: serverProposal.macAlgorithmsServerToClient,
      ),
      compressionClientToServer: _selectRequired(
        category: 'compression client->server',
        clientAlgorithms: clientProposal.compressionAlgorithmsClientToServer,
        serverAlgorithms: serverProposal.compressionAlgorithmsClientToServer,
      ),
      compressionServerToClient: _selectRequired(
        category: 'compression server->client',
        clientAlgorithms: clientProposal.compressionAlgorithmsServerToClient,
        serverAlgorithms: serverProposal.compressionAlgorithmsServerToClient,
      ),
      languageClientToServer: _selectOptional(
        clientAlgorithms: clientProposal.languagesClientToServer,
        serverAlgorithms: serverProposal.languagesClientToServer,
      ),
      languageServerToClient: _selectOptional(
        clientAlgorithms: clientProposal.languagesServerToClient,
        serverAlgorithms: serverProposal.languagesServerToClient,
      ),
      ignoreGuessedClientPacket: _shouldIgnoreGuessedPacket(
        senderProposal: clientProposal,
        selectedKeyExchange: keyExchange,
        selectedServerHostKey: serverHostKey,
      ),
      ignoreGuessedServerPacket: _shouldIgnoreGuessedPacket(
        senderProposal: serverProposal,
        selectedKeyExchange: keyExchange,
        selectedServerHostKey: serverHostKey,
      ),
    );
  }

  String _selectRequired({
    required String category,
    required List<String> clientAlgorithms,
    required List<String> serverAlgorithms,
  }) {
    final Set<String> serverAlgorithmsSet = serverAlgorithms.toSet();
    for (final String clientAlgorithm in clientAlgorithms) {
      if (serverAlgorithmsSet.contains(clientAlgorithm)) {
        return clientAlgorithm;
      }
    }

    throw SshAlgorithmNegotiationException(
      category: category,
      clientAlgorithms: clientAlgorithms,
      serverAlgorithms: serverAlgorithms,
    );
  }

  String? _selectOptional({
    required List<String> clientAlgorithms,
    required List<String> serverAlgorithms,
  }) {
    final Set<String> serverAlgorithmsSet = serverAlgorithms.toSet();
    for (final String clientAlgorithm in clientAlgorithms) {
      if (serverAlgorithmsSet.contains(clientAlgorithm)) {
        return clientAlgorithm;
      }
    }
    return null;
  }

  bool _shouldIgnoreGuessedPacket({
    required SshKexInitMessage senderProposal,
    required String selectedKeyExchange,
    required String selectedServerHostKey,
  }) {
    if (!senderProposal.firstKexPacketFollows) {
      return false;
    }

    if (senderProposal.kexAlgorithms.isEmpty ||
        senderProposal.serverHostKeyAlgorithms.isEmpty) {
      return true;
    }

    return senderProposal.kexAlgorithms.first != selectedKeyExchange ||
        senderProposal.serverHostKeyAlgorithms.first != selectedServerHostKey;
  }
}
