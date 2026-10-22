# go-arc

[![CI](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml)
[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)
[![Checklist: 47/59 mapped](https://img.shields.io/badge/checklist-47%2F59%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-arc.svg)](https://pkg.go.dev/github.com/rest-mail/go-arc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-arc)](https://goreportcard.com/report/github.com/rest-mail/go-arc)

Authenticated Received Chain ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617))
sealing and verification for Go.

It is checked item by item against the RFC in [CHECKLIST.md](CHECKLIST.md).

## About

ARC lets a message's authentication assessment survive intermediaries — mailing
lists, forwarders, and other relays that legitimately modify a message and so
break its original DKIM signature or SPF alignment. Each participating hop
records what it saw by prepending an ARC set of three header fields:
`ARC-Authentication-Results`, `ARC-Message-Signature`, and `ARC-Seal`. A
downstream receiver can then cryptographically confirm the whole chain and trust
the earliest hop's assessment even though DKIM or SPF no longer pass directly.

This package does both sides of ARC over the **raw** RFC 5322 message bytes —
never a parsed or reconstructed representation. `arc.Verify` checks an existing
chain against exactly what was transmitted; `arc.Seal` adds a new ARC set as a
forwarder would, and what `Seal` produces `Verify` accepts.

## Features

- **Sealing** (`arc.Seal`): add an ARC set — `ARC-Authentication-Results`,
  `ARC-Message-Signature`, `ARC-Seal` — for instance `i=N`, with `cv=` computed
  by verifying the chain being extended (`none`/`pass`/`fail`). Returns the
  message with the set prepended, ready to relay.
- **Verifying** (`arc.Verify`): full RFC 8617 §5.2 chain verification — the most
  recent `ARC-Message-Signature` over the message, plus every `ARC-Seal` over the
  ARC header chain up to its instance.
- Structural validation: ARC sets must be numbered contiguously `1..N`, each set
  complete.
- Returns an RFC 8617 chain-validation status — `pass`, `fail`, or `none` — with
  a human-readable reason.
- Operates on raw message bytes, the same bytes DKIM signs and verifies.
- Pluggable DNS resolver (`dkim.TXTResolver`) for tests and custom lookups; `nil`
  uses the system resolver.
- Built on [github.com/rest-mail/go-dkim](https://github.com/rest-mail/go-dkim) —
  its only dependency — so ARC shares DKIM's exact canonicalization and crypto
  path (`rsa-sha256`, relaxed canonicalization); sealing reuses the DKIM key.

## Install

```sh
go get github.com/rest-mail/go-arc
```

## Quickstart

Seal a message as a forwarder would, then verify the result — the round trip a
downstream receiver relies on. In production you would publish the public key as
a DNS TXT record and pass `nil` for the resolver (system DNS); here an in-memory
resolver serves the key so the example is self-contained.

```go
package main

import (
	"context"
	"fmt"

	arc "github.com/rest-mail/go-arc"
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

	// Seal: add an ARC set as this hop. cv= is computed from the incoming chain
	// (none here — no prior sets).
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

## Sealing

`arc.Seal` adds one ARC set for the next hop:

```go
func Seal(ctx context.Context, rawMessage []byte, opt SealOptions) (*SealResult, error)
```

`SealOptions` takes the signing identity — `Domain`, `Selector`, and
`PrivateKey` (a `*rsa.PrivateKey`, e.g. from `dkim.ParsePrivateKey`) — plus the
`AuthResults` to record and optional canonicalization / `Headers` / `Time` /
`Resolver` settings. It:

- picks the next instance `i=N` from the ARC sets already in the message;
- computes `cv=` by verifying the chain it is extending — `none` with no prior
  chain, else the `pass`/`fail` `Verify` reports (this is the only time `Seal`
  needs the resolver / DNS);
- or, when the hop changed the message (a mailing list's Subject tag or
  footer, which breaks the previous hop's signature), records the status the
  caller found by calling `Verify` on the message as it arrived, passed as
  `ChainValidation`. RFC 8617 §5.1 has every change made before sealing, so
  verify on arrival, modify, then seal;
- builds the three header fields and returns a `*SealResult` whose `Message` is
  `rawMessage` with the new set prepended, ready to relay (the individual `AAR`,
  `AMS`, and `AS` fields and the `Instance` / `ChainValidation` are exposed too).

The signing key is reused from DKIM: an `ARC-Message-Signature` is a
`DKIM-Signature` and an `ARC-Seal` a DKIM-style signature over the ARC header
chain, both `rsa-sha256`.

## Verifying

`arc.Verify` is the whole public surface:

```go
func Verify(ctx context.Context, rawMessage []byte, resolver dkim.TXTResolver) (cv, reason string)
```

It returns a chain-validation status (`"pass"`, `"fail"`, or `"none"`) and a
human-readable reason. Feed the status into a downstream `Authentication-Results`
header as `arc=<cv>`. Pass `nil` for the resolver to use system DNS, or inject a
`dkim.TXTResolver` (its signature matches `net.Resolver.LookupTXT`) in tests.

An `ARC-Message-Signature` is structurally a DKIM-Signature and an `ARC-Seal` is
a DKIM-style signature over the ARC header fields, so this package reuses the
canonicalization and signature primitives exported by go-dkim rather than
reimplementing them — ARC verification is therefore byte-for-byte consistent with
DKIM verification over the same message.

## Choices the RFC leaves open

Where RFC 8617 leaves a detail to the implementation, this package takes the
simplest secure option:

- **Tag-lists are read strictly.** In an ARC-Message-Signature or ARC-Seal, a
  repeated tag, a tag name outside RFC 6376's ABNF or an empty tag-spec
  (`;;`) fails the chain, and tag names and values are case-sensitive
  (`I=1` is not the instance, `a=RSA-SHA256` is no algorithm). The `i=` tag may
  come anywhere in those two fields, as most sealers write it; in the
  ARC-Authentication-Results it must come first, as §4.1.1's ABNF says.
- **The AMS must sign From and must not sign an ARC-Seal or
  ARC-Message-Signature** (RFC 6376 §5.4, RFC 8617 §4.1.2). An AMS that signs
  an ARC-Authentication-Results, as sealers written to the drafts did, is
  tolerated.
- **Algorithms:** the AMS is verified by go-dkim, so it may be rsa-sha256 or
  ed25519-sha256; the ARC-Seal must be rsa-sha256. rsa-sha1 fails either
  (RFC 8301). Seal signs both with rsa-sha256.
- **`d=` and `s=`** must be DNS names in A-label form (labels of 1 to 63
  letters, digits, hyphens or underscores, 253 characters at most), as go-dkim
  requires of a DKIM-Signature. Anything else fails the chain with no DNS
  query, and Seal refuses to write it. U-labels (§4.1.4) are not converted.
- **oldest-pass** (§5.2 step 5, optional) is not computed.
- **Seal stops on a failed chain.** When the most recent ARC-Seal already says
  `cv=fail`, Seal returns `ErrChainFailed` and adds nothing (§5.1 step 2);
  relay the message as it is. A chain that is broken but does not say so yet
  is sealed with `cv=fail`, its seal covering only the new set (§5.1.2).
- **By default the AMS signs** From, To, Subject, Date, Message-ID and every
  DKIM-Signature on the message (§4.1.2). Seal signs the message it is given,
  so call it after every other change, DKIM signing included (§5.1 step 1).
- **What to do with a failing chain is the receiver's policy**: §5.2 says to
  treat it like no chain at all.

## Testing

The coverage badge shows the enforced minimum; CI's RFC proof log reports the
measured statement coverage. The checklist badge counts requirements mapped to
tests, including all 12 documented `n/a` rows in its denominator of 59. These
counts describe the checked mappings; the CI badge shows whether the proof
currently passes. Tests validate both badge labels, the checklist counts and
the audited coverage workflow pin, so changes to those claims need a matching
README update.

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist         # CHECKLIST.md and the tests agree
go test -run='^$' -fuzz='^FuzzVerify$' -fuzztime=30s .
```

CI runs these through the RFC proof shared by every REST Mail library,
go-spf's
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/7d291c08d310b9c62afc287e75a534a39150fafb/.github/workflows/rfc-verification.yml),
pinned to one commit. It also fails below 95% statement coverage; the lines
left uncovered on purpose are listed, each with a reason, in
[COVERAGE.md](COVERAGE.md). The fuzz targets are `FuzzFieldInstance` (any ARC
header field value: an instance it accepts is 1 to 50) and `FuzzVerify` (any
message, seeded with valid chains of one and two sets and broken ones: the
status is `none`, `pass` or `fail`, and `none` without an ARC field); CI runs
each for 30 seconds. Inputs that once failed are kept in `testdata/fuzz`.

The [ValiMail ARC test suite](https://github.com/ValiMail/arc_test_suite)
(MIT), which OpenARC and dkimpy run, is in
[`testdata/valimail-arc-test-suite`](testdata/valimail-arc-test-suite) and all
175 of its validation tests run. It was written against draft 18 of ARC, so
six expect what RFC 8617, RFC 6376 or RFC 8301 later changed;
`suiteValidationExceptions` in `suite_test.go` lists them with the reason.
Chains of 1, 2 and 50 sets pass, 51 fail, and a chain broken at each seal fails
at that seal. RFC 8617's Appendix B examples carry no keys, so they cannot be
verified. There is no differential test: [go-msgauth](https://github.com/emersion/go-msgauth)
(v0.7.0) implements DKIM and DMARC but not ARC.

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the RFC's requirements item by item, and a
small program, [`internal/checklist`](internal/checklist/main.go), checks it
against the tests in CI. It is the same program as
[go-spf](https://github.com/rest-mail/go-spf)'s,
[go-dkim](https://github.com/rest-mail/go-dkim)'s and
[go-dmarc](https://github.com/rest-mail/go-dmarc)'s; other `go-*` libraries
can copy both.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

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

Each test names the items it covers in its doc comment:

```go
// TestSeal_StopsOnFailedChain checks that Seal adds nothing to a message whose
// most recent ARC-Seal already says cv=fail.
//
// checklist: ARC-SEAL-02
func TestSeal_StopsOnFailedChain(t *testing.T) {
```

`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-arc](https://pkg.go.dev/github.com/rest-mail/go-arc).

## Changelog

Recent releases (see [CHANGELOG.md](CHANGELOG.md) for the full history):

- **Unreleased** — go-dkim v0.3.0 (rsa-sha1 refused, ed25519-sha256 AMS
  verified); Seal returns `ErrChainFailed` on a chain that already says
  `cv=fail`, checks `d=`/`s=` and signs DKIM-Signatures; stricter ARC field
  parsing; an RFC checklist, a 95% coverage gate, fuzzing and the ValiMail
  test suite.
- **v0.2.3** — Verify now requires the ARC-Message-Signature to sign From
  (RFC 8617 §5.1.1); an AMS whose `h=` omits From is treated as cv=fail.
- **v0.2.2** — restore ARC-Message-Signature verification via go-dkim v0.2.1's
  policy-free primitive (fixing the regression from DKIM's `v=` requirement);
  RFC 8617 verify/seal fixes: 50-set cap, `cv=fail` seal scope, reject seal `h=`,
  require seal `s=`/`d=`, instance-from-highest, strict instance/tag parsing.
- **v0.2.1** — validate the ARC-Seal `cv=` chain, reject repeated ARC fields,
  ignore an unexpected AMS `v=`; go-dkim v0.1.2.
- **v0.2.0** — see the [release notes](https://github.com/rest-mail/go-arc/releases/tag/v0.2.0).
- **v0.1.1** — see the [release notes](https://github.com/rest-mail/go-arc/releases/tag/v0.1.1).
- **v0.1.0** — initial release: ARC sealing and verification (RFC 8617).

## License

[MIT](LICENSE) © 2026 rest-mail
