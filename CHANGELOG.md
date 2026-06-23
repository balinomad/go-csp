# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2026-06-23

### Added

- `Policy.Strict()`: Validation engine to catch malformed CSP syntax at startup.
- `ParseHash()`: Cryptographically secure validation and formatting for base64 hashes.
- `Policy.Clone()`: Thread-safe duplication for per-request policy mutation.

### Changed

- Optimized `Policy.Compile()` to bypass string replacement routines for static policies, reducing memory allocations.
- Refactored internal map/slice management using Go 1.21+ `slices` and `maps` packages.
- Improved locking granularity in `Compile()` to reduce write-lock contention.

### Deprecated

- `Hash()`: Replaced by `ParseHash()` to support explicit error handling.

### Fixed

- Stabilized internal cache invalidation triggers across all map mutation methods (`Add`, `Set`, `Remove`).

## [1.2.0] - 2025-09-15

### Added

- Added GoDoc documentation to unit tests.
- Added project status badges to README.md.

### Fixed

- Corrected minimum Go version requirement in `go.mod` (1.10 → 1.12).

## [1.1.0] - 2025-07-02

### Added

- Implemented core nonce injection logic to support dynamic CSP security tokens.

## [1.0.0] - 2025-07-02

### Added

- Initial release. Basic string-based CSP builder with static directive management.
