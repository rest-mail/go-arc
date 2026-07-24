// Package arc verifies Authenticated Received Chain (ARC) headers per RFC 8617.
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
// directly. This package performs that verification. It is verify-only: it does
// not add ARC sets (sealing).
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
// verification over the same message. ARC uses rsa-sha256: the ARC-Seal is
// verified with relaxed header canonicalization, and the ARC-Message-Signature
// is verified exactly as the DKIM-Signature it mirrors, honoring the
// canonicalization declared in its own c= tag.
package arc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rest-mail/go-dkim"
)

// arcSet is one ARC header set at a given instance: ARC-Authentication-Results,
// ARC-Message-Signature, ARC-Seal.
type arcSet struct {
	aar *dkim.Header
	ams *dkim.Header
	as  *dkim.Header
}

// Verify cryptographically verifies the ARC chain (RFC 8617 §5.2) in a raw
// message: the most recent ARC-Message-Signature must verify over the message
// (a DKIM-style signature), and every ARC-Seal must verify over the ARC header
// chain up to its instance. It returns a chain-validation status — "pass",
// "fail", or "none" — plus a human-readable reason. A nil resolver uses the
// system DNS resolver.
//
// Header/body canonicalization is shared with dkim.Verify (via the primitives
// exported by github.com/rest-mail/go-dkim), so ARC verification is consistent with
// DKIM verification and with any RFC 8617 verifier operating on the same bytes.
func Verify(ctx context.Context, rawMessage []byte, resolver dkim.TXTResolver) (string, string) {
	if resolver == nil {
		resolver = net.DefaultResolver.LookupTXT
	}
	headers, body := dkim.SplitMessage(rawMessage)

	sets := map[int]*arcSet{}
	get := func(i int) *arcSet {
		if sets[i] == nil {
			sets[i] = &arcSet{}
		}
		return sets[i]
	}
	for idx := range headers {
		h := &headers[idx]
		i := arcInstance(h.Value)
		if i < 1 {
			continue
		}
		switch strings.ToLower(h.Name) {
		case "arc-authentication-results":
			get(i).aar = h
		case "arc-message-signature":
			get(i).ams = h
		case "arc-seal":
			get(i).as = h
		}
	}
	if len(sets) == 0 {
		return "none", "no ARC sets present"
	}

	instances := make([]int, 0, len(sets))
	for i := range sets {
		instances = append(instances, i)
	}
	sort.Ints(instances)
	n := len(instances)

	// Chain must be contiguous 1..N with every set complete.
	for pos, i := range instances {
		if i != pos+1 {
			return "fail", fmt.Sprintf("non-contiguous chain (expected i=%d, found i=%d)", pos+1, i)
		}
		if s := sets[i]; s.aar == nil || s.ams == nil || s.as == nil {
			return "fail", fmt.Sprintf("i=%d incomplete ARC set", i)
		}
	}

	// 1. The most recent ARC-Message-Signature must verify over the message.
	amsRes := dkim.VerifySignature(ctx, *sets[n].ams, headers, body, resolver)
	if amsRes.Result != dkim.ResultPass {
		return "fail", fmt.Sprintf("ARC-Message-Signature (i=%d) %s: %s", n, amsRes.Result, amsRes.Reason)
	}

	// 2. Every ARC-Seal must verify over the ARC header chain up to its instance.
	ordered := make([]*arcSet, 0, n)
	for _, i := range instances {
		ordered = append(ordered, sets[i])
	}
	for pos, i := range instances {
		if res, reason := verifyARCSeal(ctx, ordered[:pos+1], resolver); res != dkim.ResultPass {
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) %s: %s", i, res, reason)
		}
	}

	return "pass", fmt.Sprintf("ARC chain cryptographically verified (%d set(s))", n)
}

// verifyARCSeal verifies the ARC-Seal of the LAST set in chain (ascending
// instance order) over the relaxed-canonicalized ARC header chain: for each set,
// ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal — with the final
// seal's b= emptied and no trailing CRLF (RFC 8617 §5.1.1).
func verifyARCSeal(ctx context.Context, chain []*arcSet, resolver dkim.TXTResolver) (string, string) {
	seal := chain[len(chain)-1].as
	tags := dkim.ParseTagList(seal.Value)
	if !strings.EqualFold(tags["a"], "rsa-sha256") {
		return dkim.ResultPermError, "unsupported ARC-Seal algorithm " + tags["a"]
	}
	base := arcSealBase(chain)

	sigBytes, err := base64.StdEncoding.DecodeString(dkim.StripWSP(tags["b"]))
	if err != nil {
		return dkim.ResultPermError, "invalid ARC-Seal b= base64"
	}
	pub, kres := dkim.FetchKey(ctx, tags["s"], tags["d"], resolver)
	if kres != "" {
		return kres, "ARC-Seal key lookup for " + dkim.RecordName(tags["s"], tags["d"])
	}
	hashed := dkim.HashBytes(crypto.SHA256, []byte(base))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sigBytes); err != nil {
		return dkim.ResultFail, "ARC-Seal signature verification failed"
	}
	return dkim.ResultPass, "ok"
}

// arcSealBase builds the signing input for the ARC-Seal of the last set in the
// chain: relaxed-canonicalized AAR, AMS, AS for each set in ascending order,
// each followed by CRLF except the final seal (b= emptied, no trailing CRLF).
func arcSealBase(chain []*arcSet) string {
	var b strings.Builder
	last := len(chain) - 1
	for idx, s := range chain {
		b.WriteString(dkim.CanonicalizeHeader(*s.aar, "relaxed"))
		b.WriteString("\r\n")
		b.WriteString(dkim.CanonicalizeHeader(*s.ams, "relaxed"))
		b.WriteString("\r\n")
		if idx == last {
			stripped := *s.as
			stripped.Value = dkim.RemoveBValue(s.as.Value)
			stripped.Raw = dkim.RemoveBValue(s.as.Raw)
			b.WriteString(dkim.CanonicalizeHeader(stripped, "relaxed")) // no trailing CRLF
		} else {
			b.WriteString(dkim.CanonicalizeHeader(*s.as, "relaxed"))
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// arcInstance extracts the i= instance number from an ARC header value.
func arcInstance(value string) int {
	if v := dkim.ParseTagList(value)["i"]; v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}
