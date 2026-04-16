class SshPtyMode {
  const SshPtyMode(this.opcode, this.name);

  final int opcode;
  final String name;

  static const SshPtyMode echo = SshPtyMode(53, 'ECHO');
  static const SshPtyMode canonical = SshPtyMode(51, 'ICANON');
  static const SshPtyMode signals = SshPtyMode(50, 'ISIG');
  static const SshPtyMode outputProcessing = SshPtyMode(70, 'OPOST');
}

class SshPtyConfig {
  const SshPtyConfig({
    this.terminalType = 'xterm-256color',
    this.columns = 80,
    this.rows = 24,
    this.pixelWidth = 0,
    this.pixelHeight = 0,
    this.modes = const <SshPtyMode, int>{},
  });

  final String terminalType;
  final int columns;
  final int rows;
  final int pixelWidth;
  final int pixelHeight;
  final Map<SshPtyMode, int> modes;

  SshPtyConfig copyWith({
    String? terminalType,
    int? columns,
    int? rows,
    int? pixelWidth,
    int? pixelHeight,
    Map<SshPtyMode, int>? modes,
  }) {
    return SshPtyConfig(
      terminalType: terminalType ?? this.terminalType,
      columns: columns ?? this.columns,
      rows: rows ?? this.rows,
      pixelWidth: pixelWidth ?? this.pixelWidth,
      pixelHeight: pixelHeight ?? this.pixelHeight,
      modes: modes ?? this.modes,
    );
  }
}
