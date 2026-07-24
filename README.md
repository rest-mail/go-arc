# go-arc

[![CI](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-arc.svg)](https://pkg.go.dev/github.com/rest-mail/go-arc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-arc)](https://goreportcard.com/report/github.com/rest-mail/go-arc)

Authenticated Received Chain ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617))
chain verification for Go.

## About

ARC lets a message's authentication assessment survive intermediaries — mailing
lists, forwarders, and other relays that legitimately modify a message and so
break its original DKIM signature or SPF alignment. Each participating hop
records what it saw by prepending an ARC set of three header fields:
`ARC-Authentication-Results`, `ARC-Message-Signature`, and `ARC-Seal`. A
downstream receiver can then cryptographically confirm the whole chain and trust
the earliest hop's assessment even though DKIM or SPF no longer pass directly.

This package performs that verification over the **raw** RFC 5322 message bytes —
never a parsed or reconstructed representation — so the chain is checked against
exactly what was transmitted. It is verify-only: it does not add ARC sets
(sealing).

## Features

- Full RFC 8617 §5.2 chain verification: the most recent `ARC-Message-Signature`
  over the message, plus every `ARC-Seal` over the ARC header chain up to its
  instance.
- Structural validation: ARC sets must be numbered contiguously `1..N`, each set
  complete.
- Returns an RFC 8617 chain-validation status — `pass`, `fail`, or `none` — with
  a human-readable reason.
- Operates on raw message bytes, the same bytes DKIM verifies.
- Pluggable DNS resolver (`dkim.TXTResolver`) for tests and custom lookups; `nil`
  uses the system resolver.
- Built on [github.com/rest-mail/go-dkim](https://github.com/rest-mail/go-dkim) —
  its only dependency — so ARC verification shares DKIM's exact canonicalization
  and crypto path (`rsa-sha256`, relaxed canonicalization).

## Install

```sh
go get github.com/rest-mail/go-arc
```

## Quickstart

In production you receive a message that upstream hops have already sealed, and
verify it with `arc.Verify(ctx, raw, nil)` — `nil` resolves signing keys over
system DNS. To make a runnable round trip, the example below also seals one ARC
set itself (using go-dkim's primitives, since go-arc is verify-only) and serves
the matching public key from an in-memory resolver.

```go
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	arc "github.com/rest-mail/go-arc"
	"github.com/rest-mail/go-dkim"
)

func main() {
	// One keypair signs the ARC set and answers the key lookup. Keep the private
	// key for signing; publish the public half as the DNS TXT record.
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

	sealed := sealARC(key, "example.com", "arc", raw)

	// Serve the public key from memory so the round trip needs no real DNS.
	// In production, pass nil to use the system resolver.
	txt, _ := dkim.RecordValue(pubPEM)
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name == dkim.RecordName("arc", "example.com") {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no record for %s", name)
	}

	cv, reason := arc.Verify(context.Background(), sealed, resolver)
	fmt.Printf("%s: %s\n", cv, reason)
	// Prints: pass: ARC chain cryptographically verified (1 set(s))
}

// sealARC prepends a single valid ARC set (instance 1) to raw, using only
// go-dkim's exported primitives — mirroring what a first-hop ARC sealer emits.
func sealARC(priv *rsa.PrivateKey, domain, selector string, raw []byte) []byte {
	headers, body := dkim.SplitMessage(raw)

	aar := dkim.Header{
		Name:  "ARC-Authentication-Results",
		Value: " i=1; " + domain + "; spf=pass",
		Raw:   "ARC-Authentication-Results: i=1; " + domain + "; spf=pass",
	}

	bh := base64.StdEncoding.EncodeToString(
		dkim.HashBytes(crypto.SHA256, []byte(dkim.CanonicalizeBody(body, "relaxed"))))
	hTag := "from:to:subject:date:message-id"
	amsNoB := fmt.Sprintf("i=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=",
		domain, selector, hTag, bh)
	amsForSigning := dkim.Header{Name: "ARC-Message-Signature", Value: " " + amsNoB, Raw: "ARC-Message-Signature: " + amsNoB}
	amsB := signRSA(priv, dkim.BuildSignedHeaders(hTag, headers, amsForSigning, "relaxed"))
	ams := dkim.Header{
		Name:  "ARC-Message-Signature",
		Value: " " + amsNoB + amsB,
		Raw:   "ARC-Message-Signature: " + amsNoB + amsB,
	}

	asNoB := fmt.Sprintf("i=1; a=rsa-sha256; d=%s; s=%s; cv=none; b=", domain, selector)
	asForSigning := dkim.Header{Name: "ARC-Seal", Value: " " + asNoB, Raw: "ARC-Seal: " + asNoB}
	sealBase := dkim.CanonicalizeHeader(aar, "relaxed") + "\r\n" +
		dkim.CanonicalizeHeader(ams, "relaxed") + "\r\n" +
		dkim.CanonicalizeHeader(asForSigning, "relaxed") // final seal: b= empty, no trailing CRLF
	as := dkim.Header{Name: "ARC-Seal", Raw: "ARC-Seal: " + asNoB + signRSA(priv, sealBase)}

	// ARC sets are prepended highest-instance-first: seal, signature, results.
	return []byte(as.Raw + "\r\n" + ams.Raw + "\r\n" + aar.Raw + "\r\n" + string(raw))
}

func signRSA(priv *rsa.PrivateKey, data string) string {
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, dkim.HashBytes(crypto.SHA256, []byte(data)))
	return base64.StdEncoding.EncodeToString(sig)
}
```

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

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-arc](https://pkg.go.dev/github.com/rest-mail/go-arc).

## License

[MIT](LICENSE) © 2026 rest-mail
