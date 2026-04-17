# Changelog

## 0.1.0-dev.2

- Clarified in the README that the package is public but still not ready for
  general use.
- Updated the hosted dependency example to match the current prerelease.

## 0.1.0-dev.1

- First public prerelease of `ssh_core`.
- Added a secure `dart:io` transport with Curve25519 key exchange, host-key
  verification, packet protection, compression support, and rekeying.
- Added protocol-backed auth, channels, shell sessions, exec, SFTP, and TCP
  forwarding building blocks.
- Added focused tests, smoke coverage, GitHub Actions CI, and public repository
  documentation.
