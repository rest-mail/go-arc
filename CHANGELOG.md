# Changelog

All notable changes to go-arc are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.1

Verify-path correctness fixes bringing ARC chain validation into line with
RFC 8617. The public API (`Seal`, `Verify`, `SealOptions`, `SealResult`) is
unchanged.

### Fixed

- Verify now validates the ARC-Seal `cv=` chain-validation tag and enforces a
  consistent chain state across the instances, per RFC 8617 §5.2 (#19).
- Verify now rejects a chain that repeats an ARC header field (ARC-Seal,
  ARC-Message-Signature, or ARC-Authentication-Results) at the same instance
  number, closing a header-injection gap (#20).
- Verify now ignores an unexpected `v=` tag on the ARC-Message-Signature
  instead of failing verification, per RFC 8617 §4.1.2 (#21).

### Changed

- Bumped go-dkim to v0.1.2, which fixes a panic on malformed remote key records
  (#18).

## v0.2.0

See the [GitHub release](https://github.com/rest-mail/go-arc/releases/tag/v0.2.0)
for details.

## v0.1.1

See the [GitHub release](https://github.com/rest-mail/go-arc/releases/tag/v0.1.1)
for details.

## v0.1.0

Initial release: ARC sealing and verification (RFC 8617) built on go-dkim.
