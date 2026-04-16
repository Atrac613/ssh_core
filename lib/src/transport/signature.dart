import 'dart:typed_data';

import 'message_codec.dart';

class SshSignature {
  SshSignature({
    required this.algorithm,
    required List<int> blob,
  }) : blob = Uint8List.fromList(blob);

  factory SshSignature.decode(List<int> encodedBytes) {
    final SshPayloadReader reader = SshPayloadReader(encodedBytes);
    final SshSignature signature = SshSignature(
      algorithm: reader.readString(),
      blob: reader.readStringBytes(),
    );
    reader.expectDone();
    return signature;
  }

  final String algorithm;
  final Uint8List blob;

  Uint8List encode() {
    final SshPayloadWriter writer = SshPayloadWriter()
      ..writeString(algorithm)
      ..writeStringBytes(blob);
    return writer.toBytes();
  }

  bool matches(SshSignature other) {
    if (algorithm != other.algorithm || blob.length != other.blob.length) {
      return false;
    }

    for (int index = 0; index < blob.length; index += 1) {
      if (blob[index] != other.blob[index]) {
        return false;
      }
    }

    return true;
  }
}
