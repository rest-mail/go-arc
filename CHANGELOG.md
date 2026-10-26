# Changelog

All notable changes to go-arc are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before
1.0, a minor release may carry breaking changes.

## [Unreleased]

## [0.4.0] - 2026-10-26

### Changed (breaking)

- The library is split into packages. The module path is unchanged
  (`github.com/rest-mail/go-arc`), but the root package is gone:
  - `github.com/rest-mail/go-arc/pkg/arc` holds the whole public API under
    the same names: `Verify`, `Seal`, `SealOptions`, `SealResult`,
    `ErrChainFailed` and `ErrChainValidation`.
  - `pkg/arc/internal/grammar` reads the ARC header field grammar: the
    instance tag, the strict tag-list and folding whitespace. It is internal,
    so it is not importable.
  - `pkg/arc/rfctest` runs the ValiMail ARC test suite against the public
    API. It holds tests only.

- go-arc now requires go-dkim v0.5.0, imported as
  `github.com/rest-mail/go-dkim/pkg/dkim`; before, it required v0.3.1. Go
  builds a program with one go-dkim version, so a program that also imports
  go-dkim's old root package must move to `pkg/dkim` as well.

No exported name changes. `Verify` and `Seal` behave as in v0.3.1, except that
the ARC-Message-Signature check picks up go-dkim's fixes since v0.3.1: an `l=`
longer than the body is a permerror, and an empty optional tag no longer takes
its absent-tag default.

Migration: change the import path. The package is still named `arc`, so
calls such as `arc.Verify` compile unchanged.

| Before (v0.3) | After (v0.4) |
|---------------|--------------|
| `import "github.com/rest-mail/go-arc"` or `import arc "github.com/rest-mail/go-arc"` | `import "github.com/rest-mail/go-arc/pkg/arc"` |
| `arc.Verify`, `arc.Seal`, `arc.SealOptions`, `arc.SealResult`, `arc.ErrChainFailed`, `arc.ErrChainValidation` | unchanged, now from `.../pkg/arc` |

### Changed

- CI's shared RFC proof is pinned to the go-spf workflow revision that
  measures coverage with `-coverpkg`, so the ValiMail suite in
  `pkg/arc/rfctest` counts toward `pkg/arc`.

## [0.3.1] - 2026-10-23

### Changed

- **The AAR instance reads comments** (RFC 8617 §3.9, §4.1.1): CFWS around
  `i`, `=`, the instance and the `;` after it may hold nested RFC 5322
  comments, so `i=1 (first hop);` is instance 1 instead of a malformed field
  that fails the chain. An unclosed comment is still malformed.
- **A leading AMS or AS instance reads comments too** (RFC 8617 §3.9, §4.1.2,
  §4.1.3): `(hop) i (x)= 1 (y);` at the start of an ARC-Seal is instance 1, and
  the rest of the field is still the strict tag-list, with no second `i=`. An
  AMS verifies with comments after its `=` but fails with one before `i` or
  `=`, which go-dkim's tag-list refuses (ARC-HDR-25). The README checklist
  badge now reports 48/60 mapped requirements.

- **RFC 8617 section-by-section audit:** adds 12 checklist rows and six focused
  tests for opaque assessments, independent AMS/AS identities, literal UTF-8,
  invalid historical AMSes, failed-chain restart refusal and early DNS stops.
  The audit records the remaining instance grammar tolerances, comment parsing
  gap and caller-owned result/reporting duties. Oldest-pass remains deferred.
  The README checklist badge now reports 46/58 mapped requirements.

- **README verification badges:** show the enforced ≥95% coverage gate and
  the checklist's 36/46 mapped requirements. CI checks the labels against the
  audited workflow pin and the validated checklist, including its `n/a` rows.

### Fixed

- **A hop that modifies a message can seal it with the right `cv=`**
  (RFC 8617 §5.1, §5.1.1). `Seal` computed `cv=` by verifying the bytes it was
  given, so a mailing list that tagged the Subject or added a footer before
  sealing, as §5.1 requires, recorded `cv=fail`: its own change had broken the
  previous hop's ARC-Message-Signature. The new `SealOptions.ChainValidation`
  takes the status `Verify` gave the message on arrival; a value that cannot
  describe the message (`none` on a chain, `pass` or `fail` without one, or an
  undefined value) returns `ErrChainValidation`. Empty keeps computing it from
  the message, which is right when it is sealed as received. Checklist rows
  ARC-HDR-02, ARC-HDR-06 and ARC-SEAL-01 now map to tests (39/46).

## [0.3.0] - 2026-10-17

go-arc now meets the standard of rest-mail/rest-mail-server#374: an RFC 8617
checklist checked in CI, a 95% coverage gate, fuzzing, and the ValiMail ARC
test suite. Writing the checklist found the bugs fixed below. The module is
v0.x and its only user is REST Mail's server, so where compatibility would
cost anything this is a clean break.

**What the server feels:** it calls only `Verify`, which now fails some chains
it used to pass (an AMS that signs an ARC-Seal or ARC-Message-Signature, an
rsa-sha1 or sub-1024-bit AMS, an `a=RSA-SHA256` seal, a misplaced AAR `i=`, a
malformed tag-list, a `d=` or `s=` that is not a DNS name) and passes AMSes
signed with ed25519-sha256. It does not call `Seal`.

### Breaking

- **Seal returns `ErrChainFailed`** for a message whose most recent ARC-Seal
  already says `cv=fail`, and adds nothing (RFC 8617 §5.1 step 2). It used to
  add another set.
- **Seal refuses a `Domain` or `Selector` that is not a DNS name** in A-label
  form, which Verify would have failed.

### Changed

- **go-dkim v0.3.1.** The ARC-Message-Signature is verified by its
  `VerifySignatureBare`, which now accepts ed25519-sha256 (RFC 8463) and
  refuses rsa-sha1 and RSA keys under 1024 bits (RFC 8301). The ARC-Seal stays
  rsa-sha256 only.
- **By default the AMS signs every DKIM-Signature** on the message, as RFC
  8617 §4.1.2 recommends.
- **Seals are verified from the highest instance down** (§5.2 step 6); only
  which seal a failure names changes.

### Fixed

- **Only folding whitespace counts as whitespace in ARC tag-lists and `h=`**
  (RFC 6376 §3.2; RFC 5322 §3.2.2): space, tab and CRLF folding. A form feed,
  vertical tab, NEL or no-break space around a tag name, its `=`, a value or an
  `h=` entry used to be trimmed away, so `i\f=1` read as `i=1`. go-arc's own
  parsing is fixed here, and go-dkim v0.3.1 fixes the tag-lists it parses for
  go-arc. Found by `FuzzFieldInstance` in CI, whose check now allows the
  whitespace the ABNF does.
- **An AMS that signs an ARC-Seal or ARC-Message-Signature** fails the chain
  (§4.1.2). One that signs an ARC-Authentication-Results is still tolerated.
- **Tag-lists are read strictly** (RFC 6376 §3.2): a tag name outside the
  ABNF or an empty tag-spec fails the chain, and tag names and values are
  case-sensitive, so `I=1` is not the instance, `V=` is not removed from an AMS
  and `a=RSA-SHA256` names no algorithm.
- **The ARC-Authentication-Results must start with `i=` and a `;`** (§4.1.1);
  the instance used to be read from anywhere in the field.
- **The ARC-Seal's `d=` and `s=` must be DNS names**; anything else used to be
  sent to the resolver.
- **An ARC-Seal with `a=rsa-sha1`** fails with a reason that says rsa-sha1 is
  historic.

## [0.2.3] - 2026-07-25

A single RFC 8617 §5.1.1 hardening fix on the verify path: the
ARC-Message-Signature must sign the From header. The public API (`Seal`,
`Verify`, `SealOptions`, `SealResult`) is unchanged.

### Fixed

- Verify now requires the ARC-Message-Signature to sign the From header
  (RFC 8617 §5.1.1); a chain whose AMS `h=` omits From is treated as cv=fail
  (#31).

## [0.2.2] - 2026-07-25

Restores ARC-Message-Signature verification — which regressed once go-dkim began
enforcing the RFC 6376 `v=` version rule, since a versionless ARC-Message-Signature
(RFC 8617 §4.1.2) carries no `v=` — together with a set of RFC 8617 verify/seal
correctness fixes. The public API (`Seal`, `Verify`, `SealOptions`, `SealResult`)
is unchanged.

### Changed

- Bumped go-dkim to v0.2.1 and switched ARC-Message-Signature verification onto
  its new policy-free primitive (`dkim.VerifySignatureBare`): ARC now verifies the
  DKIM crypto mechanism and applies RFC 8617 policy itself, rather than inheriting
  RFC 6376 DKIM policy. This fixes ARC verification, which DKIM's `v=` requirement
  had broken for the versionless ARC-Message-Signature (RFC 8617 §4.1.2).

### Fixed

- Verify now enforces the RFC 8617 §5.1.1 maximum of 50 ARC sets before any
  structural or cryptographic check (#9, #24).
- Seal now scopes a `cv=fail` ARC-Seal to the current set only, never signing the
  prior (failed) chain, per RFC 8617 §5.1.2 (#25).
- Verify and Seal now reject an ARC-Seal that carries a forbidden `h=` tag, per
  RFC 8617 §4.1.3 (#26).
- The ARC-Seal now requires its `s=` (selector) and `d=` (domain) tags, with no
  fallback to a substituted default selector (#27).
- Seal now derives the new set's instance number from the highest instance
  present rather than the count of prior sets, so a gapped chain no longer
  collides at an existing instance (#28).
- Verify and Seal now validate ARC instance numbers strictly, reject a repeated
  DKIM tag in an ARC-Message-Signature or ARC-Seal, and sanitize Seal output
  against header injection (#29).
- Seal now rejects an incomplete prior ARC set instead of panicking (#23).

## [0.2.1] - 2026-07-25

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

## [0.2.0] - 2026-07-24

See the [GitHub release](https://github.com/rest-mail/go-arc/releases/tag/v0.2.0)
for details.

## [0.1.1] - 2026-07-23

See the [GitHub release](https://github.com/rest-mail/go-arc/releases/tag/v0.1.1)
for details.

## [0.1.0] - 2026-07-23

Initial release: ARC sealing and verification (RFC 8617) built on go-dkim.
