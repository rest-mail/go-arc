// Package arc seals and verifies Authenticated Received Chain (ARC) header
// fields per RFC 8617.
//
// ARC lets a message's authentication assessment survive intermediaries —
// mailing lists, forwarders, and other relays that legitimately modify a message
// and so break its original DKIM signature or SPF alignment. Each participating
// hop records what it saw by prepending an ARC set of three header fields:
//
//   - ARC-Authentication-Results (AAR): the authentication results the hop observed;
//   - ARC-Message-Signature (AMS): a DKIM-style signature over the message;
//   - ARC-Seal (AS): a signature over the chain of ARC header fields so far.
//
// A downstream receiver can then cryptographically confirm the whole chain and
// trust the earliest hop's assessment even though DKIM or SPF no longer pass
// directly. This package does both sides: Verify checks an existing chain, and
// Seal adds a new set as a forwarder — what Seal produces, Verify accepts.
//
// # Verifying
//
// Verify checks a raw RFC 5322 message and returns a chain-validation status
// together with a human-readable reason:
//
//	cv, reason := arc.Verify(ctx, raw, nil) // nil resolver → system DNS
//	fmt.Printf("arc=%s (%s)\n", cv, reason)
//
// It validates both the chain's structure — ARC sets numbered contiguously
// 1..N, each set complete — and its cryptography (RFC 8617 §5.2): the most
// recent ARC-Message-Signature must verify over the message, and every ARC-Seal
// must verify over the ARC header chain up to its instance. Signing keys are
// fetched from DNS at <selector>._domainkey.<domain>; pass a dkim.TXTResolver to
// override the lookup (for tests or a custom resolver), or nil for system DNS.
//
// # Sealing
//
// Seal is the counterpart to Verify: a forwarder adds one ARC set — an
// ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal for instance
// i=N — and returns the message with the set prepended, ready to relay. It
// records cv= by verifying the chain it is extending: "none" when there is no
// prior chain, otherwise the "pass"/"fail" Verify reports for the message as
// received.
//
//	res, err := arc.Seal(ctx, raw, arc.SealOptions{
//		Domain:      "example.com",
//		Selector:    "arc",
//		PrivateKey:  key, // *rsa.PrivateKey, e.g. from dkim.ParsePrivateKey
//		AuthResults: "example.com; spf=pass smtp.mailfrom=a@example.com",
//	})
//	// res.Message is raw with the new ARC set prepended; relay it.
//
// The ARC-Message-Signature is structurally a DKIM-Signature and the ARC-Seal a
// DKIM-style signature over the ARC header chain, both rsa-sha256, so sealing
// reuses the DKIM signing key and the same go-dkim canonicalization the verifier
// uses — what Seal produces, Verify (and any conformant RFC 8617 verifier)
// accepts over the exact transmitted bytes.
//
// # Status values
//
// The status is one of three RFC 8617 chain-validation values:
//
//   - "pass" — the chain is present and cryptographically intact;
//   - "fail" — the chain is present but broken: a bad signature, a tampered
//     field, or a structurally invalid chain;
//   - "none" — the message carries no ARC sets.
//
// Record it in a downstream Authentication-Results header as arc=<status>.
//
// # Building on go-dkim
//
// An ARC-Message-Signature is structurally a DKIM-Signature, and an ARC-Seal is
// a DKIM-style signature over the ARC header fields. This package therefore
// reuses the canonicalization and signature primitives exported by
// github.com/rest-mail/go-dkim — its only dependency — rather than
// reimplementing them, so ARC verification is byte-for-byte consistent with DKIM
// verification over the same message. The ARC-Seal is rsa-sha256, verified
// with relaxed header canonicalization, and the ARC-Message-Signature is
// verified exactly as the DKIM-Signature it mirrors (rsa-sha256 or
// ed25519-sha256; rsa-sha1 is refused, RFC 8301), honoring the
// canonicalization declared in its own c= tag — except that, per RFC 8617
// §4.1.2, the AMS is not versioned: any v= tag it carries is not part of it and
// is ignored rather than checked against the DKIM version rule.
package arc
