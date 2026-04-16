enum SftpFileType { file, directory, symlink, special, unknown }

class SftpFileEntry {
  const SftpFileEntry({
    required this.path,
    required this.type,
    this.size,
    this.modifiedAt,
  });

  final String path;
  final SftpFileType type;
  final int? size;
  final DateTime? modifiedAt;
}

abstract class SftpClient {
  Future<List<SftpFileEntry>> listDirectory(String path);

  Future<List<int>> readFile(String path);

  Future<void> writeFile(String path, List<int> bytes);

  Future<void> createDirectory(String path, {bool recursive = false});

  Future<void> delete(String path, {bool recursive = false});

  Future<void> close();
}

abstract class SftpSubsystem {
  Future<SftpClient> open();
}
