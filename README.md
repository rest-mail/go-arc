# go-arc

[![CI](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml)
[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)
[![Checklist: 48/60 mapped](https://img.shields.io/badge/checklist-48%2F60%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-arc.svg)](https://pkg.go.dev/github.com/rest-mail/go-arc/pkg/arc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-arc)](https://goreportcard.com/report/github.com/rest-mail/go-arc)

Authenticated Received Chain ([RFC 8617]) sealing and verification for Go.

ARC lets a message's authentication assessment survive intermediaries: mailing
lists, forwarders and other relays that legitimately change a message and so
break its original DKIM signature or SPF alignment. Each hop that takes part
records what it saw by prepending an ARC set of three header fields:
`ARC-Authentication-Results`, `ARC-Message-Signature` and `ARC-Seal`. A
receiver further on can check the whole chain and trust the earliest hop's
assessment even though DKIM or SPF no longer pass directly.

go-arc does both sides, over the raw RFC 5322 message bytes, never a parsed or
rebuilt copy: `arc.Verify` checks the chain a message carries, and `arc.Seal`
adds a new set as a forwarder would. What `Seal` produces, `Verify` accepts. It
is built on [go-dkim](https://github.com/rest-mail/go-dkim), its only
dependency, so ARC shares DKIM's canonicalization and signature code.

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start](#quick-start): [seal and verify](#seal-and-verify), [seal a message you changed](#seal-a-message-you-changed)
- [Features](#features)
- [What the library does and what the host must do](#what-the-library-does-and-what-the-host-must-do)
- [RFC conformance](#rfc-conformance): [the checklist](#the-rfc-checklist), [what it does not do](#what-it-does-not-do), [badges and coverage](#badges-and-coverage)
- [Changelog](#changelog)
- [Licence](#licence)

## Install

```sh
go get github.com/rest-mail/go-arc@latest
```

The module declares go 1.25.

## Packages

| Import path | What it holds |
|-------------|---------------|
| `github.com/rest-mail/go-arc/pkg/arc` | The whole public API: `Verify`, `Seal`, `SealOptions`, `SealResult`, `ErrChainFailed` and `ErrChainValidation`. |
| `pkg/arc/internal/grammar` | The ARC header field grammar: the instance tag, with the comments RFC 8617 §3.9 allows around a leading instance, the strict RFC 6376 tag-list and folding whitespace. Internal: not importable. |
| `pkg/arc/rfctest` | The ValiMail ARC test suite, run against the public API only. Tests only. |

Upgrading from v0.3 or earlier: the root package is gone, and the import path
is now `github.com/rest-mail/go-arc/pkg/arc`. The package is still named `arc`
and no name changed. [CHANGELOG.md](CHANGELOG.md#040---2026-10-26) has the
old-to-new table.

## Quick start

### Seal and verify

Seal a message as a forwarder would, then verify the result: the round trip a
receiver further on relies on. In production you publish the public key as a
DNS TXT record and pass `nil` for the resolver, so the system DNS is used; here
an in-memory resolver serves the key, so the example runs on its own.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-arc/pkg/arc"
	"github.com/rest-mail/go-dkim"
)

func main() {
	// Keep the private key for signing; publish the public half as the DNS record.
	privPEM, pubPEM, err := dkim.GenerateKey(2048)
	if err != nil {
		panic(err)
	}
	key, err := dkim.ParsePrivateKey(privPEM)
	if err != nil {
		panic(err)
	}

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: hello\r\n" +
		"Date: Thu, 23 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <1@example.com>\r\n" +
		"\r\n" +
		"Hello, world!\r\n")

	// Serve the public key from memory so the round trip needs no real DNS.
	// In production, pass nil to use the system resolver.
	txt, _ := dkim.RecordValue(pubPEM)
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name == dkim.RecordName("arc", "example.com") {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no record for %s", name)
	}

	// Seal: add an ARC set as this hop. cv= comes from the incoming chain
	// (none here: there are no earlier sets).
	res, err := arc.Seal(context.Background(), raw, arc.SealOptions{
		Domain:      "example.com",
		Selector:    "arc",
		PrivateKey:  key,
		AuthResults: "example.com; spf=pass smtp.mailfrom=alice@example.com",
		Resolver:    resolver,
	})
	if err != nil {
		panic(err)
	}

	// Verify what we just sealed.
	cv, reason := arc.Verify(context.Background(), res.Message, resolver)
	fmt.Printf("sealed i=%d cv=%s -> verify %s: %s\n", res.Instance, res.ChainValidation, cv, reason)
	// Prints: sealed i=1 cv=none -> verify pass: ARC chain cryptographically verified (1 set(s))
}
```

### Seal a message you changed

RFC 8617 §5.1 has a hop make every change before it seals. A mailing list
that tags the Subject or adds a footer breaks the previous hop's
ARC-Message-Signature, so verifying the changed message would record
`cv=fail`. Verify the message as it arrived, change it, then seal with the
status you found:

```go
cv, _ := arc.Verify(ctx, received, nil) // "none", "pass" or "fail"

changed := addListFooter(received) // your change, DKIM signing included

res, err := arc.Seal(ctx, changed, arc.SealOptions{
	Domain:          "lists.example.org",
	Selector:        "arc",
	PrivateKey:      key,
	AuthResults:     "lists.example.org; dkim=pass header.d=example.com",
	ChainValidation: cv,
})
if errors.Is(err, arc.ErrChainFailed) {
	// The most recent ARC-Seal already says cv=fail: relay the message unsealed.
}
```

`Example` and `ExampleSeal` in [`pkg/arc/example_test.go`](pkg/arc/example_test.go)
run on every test.

## Features

| Feature | RFC | API |
|---------|-----|-----|
| Chain verification: the most recent ARC-Message-Signature over the message, and every ARC-Seal over the ARC fields up to its instance, from the highest instance down | RFC 8617 §5.2 | `Verify` |
| Chain structure: sets numbered 1 to N with no gap, each set complete, one field of each kind per instance, at most 50 sets | RFC 8617 §4.2.1, §5.2 | `Verify` |
| `cv=` consistency: `none` at instance 1, `pass` at every later one | RFC 8617 §5.2 | `Verify` |
| Strict field grammar: the instance tag, comments around a leading instance, RFC 6376 tag-lists, case-sensitive tags | RFC 8617 §3.9, §4.1; RFC 6376 §3.2 | `Verify`, `Seal` |
| Sealing: the AAR, AMS and AS for instance N, with `cv=` from the incoming chain, prepended to the message | RFC 8617 §5.1 | `Seal` |
| Sealing a changed message with the status found on arrival | RFC 8617 §5.1, §5.1.1 | `SealOptions.ChainValidation` |
| A failed chain is not continued; a broken chain is sealed with `cv=fail`, its seal covering the new set only | RFC 8617 §5.1, §5.1.2 | `Seal`, `ErrChainFailed` |
| Algorithms: the AMS verifies with rsa-sha256 or ed25519-sha256, the ARC-Seal with rsa-sha256; rsa-sha1 fails; Seal signs with rsa-sha256 | RFC 8301, RFC 8463 | `Verify`, `Seal` |
| Canonicalization: the AMS honours its `c=`, relaxed or simple; the ARC-Seal is relaxed | RFC 8617 §4.1.2, §4.1.3 | `Verify`, `SealOptions.HeaderCanon`, `SealOptions.BodyCanon` |
| Key lookup through any `dkim.TXTResolver`, or the system DNS with `nil` | RFC 6376 §3.6.2 | `Verify`, `SealOptions.Resolver` |

`Verify` returns the chain validation status, `"pass"`, `"fail"` or `"none"`,
and a human-readable reason:

```go
func Verify(ctx context.Context, rawMessage []byte, resolver dkim.TXTResolver) (string, string)
func Seal(ctx context.Context, rawMessage []byte, opt SealOptions) (*SealResult, error)
```

`SealResult` holds the new `Instance`, the `ChainValidation` recorded in the
seal, the three fields `AAR`, `AMS` and `AS`, and the `Message` with the set
prepended, ready to relay.

## What the library does and what the host must do

Each area says what go-arc handles and what stays with the host, the program
that calls it. The [checklist](CHECKLIST.md) records these boundaries row by
row.

### Verifying

The library:

- Checks the chain's structure and every `cv=` before it queries DNS, so a
  malformed chain fails without a key lookup.
- Reads tag-lists strictly. In an ARC-Message-Signature or ARC-Seal, a
  repeated tag, a tag name outside RFC 6376's ABNF or an empty tag-spec
  (`;;`) fails the chain, and tag names and values are case-sensitive (`I=1`
  is not the instance, `a=RSA-SHA256` is no algorithm).
- Reads the instance by RFC 8617 §3.9 and §4.1. In the
  ARC-Authentication-Results, `i=` comes first, as §4.1.1 says. In the
  ARC-Message-Signature and ARC-Seal it may come anywhere, as most sealers
  write it. A leading instance may carry RFC 5322 comments: `(hop) i=1;` is
  instance 1 in any of the three fields.
- Requires the AMS to sign From, and refuses an AMS that signs an ARC-Seal or
  ARC-Message-Signature (RFC 6376 §5.4, RFC 8617 §4.1.2). An AMS that signs an
  ARC-Authentication-Results, as sealers written to the drafts did, is
  tolerated.
- Ignores a `v=` tag on an AMS: the AMS is not versioned (RFC 8617 §4.1.2).
- Requires the `d=` and `s=` of each signature to be DNS names in A-label
  form: labels of 1 to 63 letters, digits, hyphens or underscores, 253
  characters at most. Anything else fails the chain with no DNS query.

The host:

- Passes the message exactly as received; any change made before `Verify`
  breaks the signatures.
- Records the status in its own Authentication-Results field as `arc=<status>`.
- Decides what a status means for delivery. RFC 8617 §5.2 says to treat a
  failing chain like no chain at all, and a passing chain is not a trust
  verdict: whether to honour a sealer's assessment is local policy.

### Sealing

The library:

- Picks the next instance, one past the highest on the message, and refuses
  to add a 51st set.
- Computes `cv=` by verifying the message it is given, unless the caller gives
  `ChainValidation`; a value that cannot describe the message returns
  `ErrChainValidation`.
- Returns `ErrChainFailed` and adds nothing when the most recent ARC-Seal
  already says `cv=fail` (§5.1 step 2). A chain that is broken but does not say
  so yet is sealed with `cv=fail`, its seal covering only the new set
  (§5.1.2).
- Signs From, To, Subject, Date, Message-ID and every DKIM-Signature on the
  message by default (§4.1.2), or the headers in `SealOptions.Headers`; only
  headers present in the message are signed.
- Refuses a `Domain` or `Selector` that is not a DNS name in A-label form, and
  a CR or LF in `Domain`, `Selector` or `AuthResults`, so no input can add a
  header field.
- Rejects an incoming chain with an incomplete set.

The host:

- Makes every change to the message before it seals, DKIM signing included
  (§5.1 step 1), and passes the status it found on arrival in
  `ChainValidation` when it changed the message.
- Supplies the RSA signing key and publishes its public half at
  `<selector>._domainkey.<domain>`.
- Supplies the `AuthResults` to record: its own assessment of the message as
  it arrived. Empty records `<domain>; none`.

## RFC conformance

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists RFC 8617's requirements on a validator and
on a sealer, item by item, with the rules ARC takes from DKIM (RFC 6376,
RFC 8301 and RFC 8463) where ARC relies on them. Each mapped row names the
tests that prove it. Rows the library does not meet, or that belong to the
host, are `n/a` with the reason.

The checklist is a Markdown file of tables with this header:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-HDR-13 | 4.1.3 | MUST | An ARC-Seal carrying an `h=` tag makes the chain fail. | `TestVerifyARC_SealWithHTagRejected` |
| ARC-VAL-14 | 5.2.2 | MAY | Reject a failing message in SMTP with 5.7.29 or 5.7.26. | n/a: the library speaks no SMTP. |
```

- **ID** is unique, upper case, and ends in a number: a prefix for the RFC, an
  area, and a sequence number (`ARC-HDR-13`).
- **Section** is the RFC section (or sections) the requirement comes from.
- **Level** is the RFC 2119 keyword it carries (`MUST`, `MUST NOT`, `SHOULD`,
  `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY`, ...), or `Normative`
  for normative text without a keyword.
- **Requirement** says what is required, in one line (no `|`).
- **Tests** lists the test functions that cover it, separated by commas, or
  says `n/a:` and why it does not apply.

Each test names the rows it covers in its doc comment:

```go
// TestSeal_StopsOnFailedChain checks that Seal adds nothing to a message whose
// most recent ARC-Seal already says cv=fail.
//
// checklist: ARC-SEAL-02
func TestSeal_StopsOnFailedChain(t *testing.T) {
```

[`internal/checklist`](internal/checklist/main.go) checks one against the
other in CI. It is the same program as the other `go-*` libraries'.
`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` fails
when an ID is used twice or a row is malformed, a row names no test and is not
`n/a`, a row and a test disagree about each other, or a `Test` or `Fuzz`
function names no row (`Example` functions may):

```sh
go run ./internal/checklist ./pkg/arc ./pkg/arc/internal/grammar ./pkg/arc/rfctest
```

### What it does not do

Some gaps are deliberate, and go-arc will not fill them. Others are planned,
each with an issue. The checklist records every one as an `n/a` row with its
reason.

#### Not supported, by design

| Area | What go-arc does | Why |
|------|------------------|-----|
| Internationalized domain names | `d=` and `s=` must be A-labels: a U-label fails the chain, and Seal refuses one (ARC-HDR-16). | Converting needs IDNA tables, which go-arc does not carry; go-dkim refuses U-labels in a DKIM-Signature too, and no sealer seen in practice writes them. |
| Several algorithms at one instance | A second field of one kind at an instance fails the chain (ARC-SET-03). | That is the ARC-MULTI draft, which expired; RFC 8617 has one set per instance. |
| Instance position in the AMS and ARC-Seal | `i=` may come anywhere in their tag-lists, not only first, as their ABNF puts it (ARC-HDR-22). | Many sealers write it elsewhere, and refusing them would fail real chains. The ARC-Authentication-Results' `i=` must come first. |
| Receiver policy | `Verify` returns a status and a reason. It writes no Authentication-Results field, sends no SMTP reply, and makes no delivery decision or DMARC report (ARC-VAL-11, ARC-VAL-12, ARC-VAL-14, ARC-RES-02, ARC-POLICY-01, ARC-POLICY-02). | Those need the SMTP session and the receiver's own policy, which the library does not have. |

#### Not planned

| Area | What go-arc does |
|------|------------------|
| ed25519-sha256 ARC-Seals | Seal signs with rsa-sha256 only, and an ed25519-sha256 ARC-Seal fails the chain. An ed25519-sha256 AMS verifies. |
| Comments before `i` or `=` in an AMS | go-arc reads them, but go-dkim, which checks the AMS signature, refuses them, so the chain fails (ARC-HDR-25). A comment after the `=` verifies. Supporting the rest needs a go-dkim API that verifies tags the caller parsed. |

#### Planned

| Gap | Issue |
|-----|-------|
| `Verify` returns only a status and a reason. A host that trusts some sealers, or reports an ARC-influenced decision in DMARC, needs the chain's sealers and what each hop recorded. | [#43](https://github.com/rest-mail/go-arc/issues/43) |
| The oldest ARC-Message-Signature that still verifies (oldest-pass, §5.2 step 5) is not computed, so the host cannot record `header.oldest-pass` (ARC-VAL-08, ARC-RES-01). | [#44](https://github.com/rest-mail/go-arc/issues/44) |

### Badges and coverage

The badges at the top are checked by `TestReadmeChecklistBadge` and
`TestReadmeCoverageBadge` in `internal/checklist`. The checklist badge counts
mapped rows over all rows: the `n/a` rows are in the denominator, so the badge
never claims more than the tests prove. The coverage badge shows the floor CI
enforces, not a measured figure; CI's RFC proof log prints the measured
statement coverage. Coverage exceptions, each with its reason, are in
[COVERAGE.md](COVERAGE.md).

CI runs the RFC proof shared by every REST Mail library, go-spf's
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/7d291c08d310b9c62afc287e75a534a39150fafb/.github/workflows/rfc-verification.yml),
pinned to one commit: build, vet, golangci-lint, the race tests with the 95%
coverage gate, the checklist, and each fuzz target for 30 seconds.
`TestReadmeCoverageBadge` fails when the pin changes, so the gate is
re-checked.

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist ./pkg/arc ./pkg/arc/internal/grammar ./pkg/arc/rfctest
go test -run='^$' -fuzz='^FuzzVerify$' -fuzztime=30s ./pkg/arc
```

Two fuzz targets run in CI: `FuzzFieldInstance` in `pkg/arc/internal/grammar`
reads any ARC header field value (an instance it accepts is 1 to 50), and
`FuzzVerify` in `pkg/arc` verifies any message, seeded with valid chains of
one and two sets and broken ones (the status is `none`, `pass` or `fail`, and
`none` without an ARC field). Inputs that once failed are kept in each
package's `testdata/fuzz`.

The [ValiMail ARC test suite](https://github.com/ValiMail/arc_test_suite)
(MIT), which OpenARC and dkimpy run, is in
[`pkg/arc/rfctest/testdata/valimail-arc-test-suite`](pkg/arc/rfctest/testdata/valimail-arc-test-suite),
and all 175 of its validation tests run. It was written against draft 18 of
ARC, so six expect what RFC 8617, RFC 6376 or RFC 8301 later changed;
`suiteValidationExceptions` in
[`pkg/arc/rfctest/suite_test.go`](pkg/arc/rfctest/suite_test.go) lists them
with the reason. Chains of 1, 2 and 50 sets pass, 51 fail, and a chain broken
at each seal fails at that seal. RFC 8617's Appendix B examples carry no keys,
so they cannot be verified. There is no differential test:
[go-msgauth](https://github.com/emersion/go-msgauth) (v0.7.0) implements DKIM
and DMARC but not ARC.

## Changelog

Recent releases; see [CHANGELOG.md](CHANGELOG.md) for the complete history.

### v0.4.0 (2026-10-26)

The library moves to `pkg/arc` (breaking: change the import path; the
changelog has a migration table). `Verify` and `Seal` behave as in v0.3.1.

### v0.3.1 (2026-10-23)

A hop that changes a message can seal it with the status it found on arrival
(`SealOptions.ChainValidation`). Comments around a leading instance are read
in all three ARC fields.

### v0.3.0 (2026-10-17)

go-dkim v0.3.1: an ed25519-sha256 AMS verifies, and rsa-sha1 fails. Seal
returns `ErrChainFailed` on a chain that already says `cv=fail` and refuses a
`d=` or `s=` that is not a DNS name (breaking), and the AMS signs every
DKIM-Signature by default. Stricter field parsing, an RFC checklist, a 95%
coverage gate, fuzzing and the ValiMail test suite.

### v0.2.3 (2026-07-25)

`Verify` requires the ARC-Message-Signature to sign From (RFC 8617 §5.1.1).

### v0.2.2 (2026-07-25)

AMS verification restored on go-dkim v0.2.1. The 50-set limit, the `cv=fail`
seal scope, a refused seal `h=`, required seal `s=` and `d=`, the instance
from the highest present, and strict instance and tag parsing.

### v0.2.1 (2026-07-25)

The ARC-Seal `cv=` chain is validated, repeated ARC fields are refused, and an
unexpected AMS `v=` is ignored; go-dkim v0.1.2.

## Licence

[MIT](LICENSE) © 2026 rest-mail

[RFC 8617]: https://www.rfc-editor.org/rfc/rfc8617
