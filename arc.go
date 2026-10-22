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
// verification over the same message. ARC uses rsa-sha256: the ARC-Seal is
// verified with relaxed header canonicalization, and the ARC-Message-Signature
// is verified exactly as the DKIM-Signature it mirrors, honoring the
// canonicalization declared in its own c= tag — except that, per RFC 8617
// §4.1.2, the AMS is not versioned: any v= tag it carries is not part of it and
// is ignored rather than checked against the DKIM version rule.
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

	sets, err := collectARCSets(headers)
	if err != nil {
		return "fail", err.Error()
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

	// RFC 8617 §5.2 step 1 / §4.2.1: a message may carry at most 50 ARC sets. If
	// more exist, the chain-validation status is "fail" and the algorithm stops
	// here — before any structural or cryptographic checks. Enforcing the ceiling
	// first also bounds the work an inbound message can drive: each ARC-Seal is
	// verified by re-canonicalizing every prior set (O(n²)) with one DNS key
	// lookup per set, so an unbounded chain is a denial-of-service vector.
	if n > maxARCSets {
		return "fail", fmt.Sprintf("ARC chain has %d sets, exceeding the RFC 8617 maximum of %d", n, maxARCSets)
	}

	// Chain must be contiguous 1..N with every set complete.
	for pos, i := range instances {
		if i != pos+1 {
			return "fail", fmt.Sprintf("non-contiguous chain (expected i=%d, found i=%d)", pos+1, i)
		}
		if s := sets[i]; s.aar == nil || s.ams == nil || s.as == nil {
			return "fail", fmt.Sprintf("i=%d incomplete ARC set", i)
		}
	}

	// Each ARC-Seal's cv= (chain-validation) tag must be internally consistent
	// (RFC 8617 §5.2 steps 2 & 3C): "none" at i=1 and "pass" at every i>1. A
	// verifier must not trust an asserted cv=, but a self-inconsistent one is
	// conclusive on its own — a highest-instance cv=fail means a prior verifier
	// already declared the chain broken (§5.2 step 2), and cv=fail, a missing
	// tag, or any other value at any position describes a chain the RFC says can
	// never be continued (§5.1.3). Treat all of these as chain status "fail",
	// before the cryptographic checks, so an intact-but-laundered chain cannot
	// verify as "pass".
	for _, i := range instances {
		asTags := dkim.ParseTagList(sets[i].as.Value)

		// RFC 8617 §4.1.3: an ARC-Seal always covers the entire set of ARC header
		// fields, so — unlike the ARC-Message-Signature — it MUST NOT carry an h=
		// tag. A seal that includes one is malformed (even a bare "h="), and a
		// verifier MUST treat the chain as broken. Reject it here, before the
		// cryptographic checks, so a crafted h= (which arcSealBase does not honour)
		// cannot ride along on an otherwise-valid seal signature and launder the
		// chain to "pass".
		if _, ok := asTags["h"]; ok {
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) carries a forbidden h= tag (RFC 8617 §4.1.3)", i)
		}

		cv := strings.ToLower(trimFWS(asTags["cv"]))
		want := "pass"
		if i == 1 {
			want = "none"
		}
		if cv != want {
			shown := cv
			if shown == "" {
				shown = "(absent)"
			}
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) cv=%s, expected cv=%s", i, shown, want)
		}
	}

	// The AMS h= list (RFC 8617 §4.1.2), checked before any DNS query. The AMS has
	// DKIM-Signature semantics, and RFC 6376 §5.4 makes From mandatory in h=:
	// an AMS that does not sign From does not bind the author identity, so the
	// chain is broken even if the signature is cryptographically valid. The
	// policy-free dkim.VerifySignatureBare below does not apply that rule, so it
	// is asserted here. The AMS also MUST NOT cover the ARC header fields; an AMS
	// that signs an ARC-Seal or ARC-Message-Signature is refused, as dkimpy and
	// the ValiMail ARC test suite do. One that signs ARC-Authentication-Results,
	// as draft-era sealers did, is tolerated (see the README).
	amsH := dkim.ParseTagList(sets[n].ams.Value)["h"]
	if !amsSignsFrom(amsH) {
		return "fail", fmt.Sprintf("ARC-Message-Signature (i=%d) h= does not sign the From header (RFC 6376 §5.4)", n)
	}
	if f := amsSignsARC(amsH); f != "" {
		return "fail", fmt.Sprintf("ARC-Message-Signature (i=%d) h= signs %s (RFC 8617 §4.1.2)", n, f)
	}

	// 1. The most recent ARC-Message-Signature must verify over the message.
	//
	// Verify only the DKIM crypto MECHANISM here, via the policy-free primitive:
	// an ARC-Message-Signature is structurally a DKIM-Signature but versionless by
	// design (RFC 8617 §4.1.2) and governed by ARC's rules, not RFC 6376 DKIM
	// policy. dkim.VerifySignature would PERMFAIL it on the missing v= tag (and
	// would additionally impose From-signed / i= alignment / t=/x= timing / key
	// t=s / s= flags that the AMS does not answer to). dkim.VerifySignatureBare
	// runs the same header-select + canonicalize + hash + verify against the
	// d=/s= key with NONE of that policy; a ResultPass means the AMS crypto is
	// valid. It verifies rsa-sha256 and ed25519-sha256 and refuses rsa-sha1 and
	// RSA keys under 1024 bits (RFC 8301, RFC 8463). ARC's own policy — chain cv=,
	// contiguous instance ordering, seal h=-prohibited, seal s=/d= required, the
	// AMS h= rules above — is enforced in this function.
	amsRes := dkim.VerifySignatureBare(ctx, *sets[n].ams, headers, body, resolver)
	if amsRes.Result != dkim.ResultPass {
		return "fail", fmt.Sprintf("ARC-Message-Signature (i=%d) %s: %s", n, amsRes.Result, amsRes.Reason)
	}

	// 2. Every ARC-Seal must verify over the ARC header chain up to its
	// instance, from the greatest instance down to 1 (RFC 8617 §5.2 step 6).
	ordered := make([]*arcSet, 0, n)
	for _, i := range instances {
		ordered = append(ordered, sets[i])
	}
	for i := n; i >= 1; i-- {
		if res, reason := verifyARCSeal(ctx, ordered[:i], resolver); res != dkim.ResultPass {
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) %s: %s", i, res, reason)
		}
	}

	return "pass", fmt.Sprintf("ARC chain cryptographically verified (%d set(s))", n)
}

// verifyARCSeal verifies the ARC-Seal of the LAST set in chain (ascending
// instance order) over the relaxed-canonicalized ARC header chain: for each set,
// ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal — with the final
// seal's b= emptied and no trailing CRLF (RFC 8617 §5.1.1, RFC 6376 §3.7).
func verifyARCSeal(ctx context.Context, chain []*arcSet, resolver dkim.TXTResolver) (string, string) {
	seal := chain[len(chain)-1].as
	tags := dkim.ParseTagList(seal.Value)
	// Tag values are case-sensitive (RFC 6376 §3.2), so "RSA-SHA256" is not
	// rsa-sha256. rsa-sha1 is historic (RFC 8301 §3.1). The seal key comes from
	// dkim.FetchKey, which returns RSA keys only, so ed25519-sha256 is not
	// verified here (see the README).
	switch tags["a"] {
	case "rsa-sha256":
	case "rsa-sha1":
		return dkim.ResultPermError, "rsa-sha1 is historic and no longer verified (RFC 8301)"
	default:
		return dkim.ResultPermError, "unsupported ARC-Seal algorithm " + tags["a"]
	}

	// RFC 8617 §4.1.3: the ARC-Seal's s= (selector) and d= (domain) are REQUIRED
	// tags — together they name the public key at s=._domainkey.d= that verifies
	// the seal. A seal missing either is malformed and MUST NOT verify. This guard
	// is load-bearing, not defensive: dkim.FetchKey/dkim.RecordName substitute the
	// selector "default" for an empty s=, so a seal that simply omits s= would
	// otherwise resolve default._domainkey.<d> and verify against whatever key
	// happens to live there — a verification-integrity hole where an attacker drops
	// s= to pivot onto a selector that resolves. Reject the seal (chain status
	// "fail") here rather than fall back to a substituted selector. (The AMS path
	// is already safe: it verifies via dkim.VerifySignatureBare, which — like the
	// full primitive — requires s= among its mechanism tags.)
	if tags["s"] == "" {
		return dkim.ResultPermError, "ARC-Seal missing required s= (selector) tag"
	}
	if tags["d"] == "" {
		return dkim.ResultPermError, "ARC-Seal missing required d= (domain) tag"
	}
	// d= and s= name a DNS record, in A-label form as go-dkim requires of the
	// AMS too; anything else is not sent to the resolver.
	if !validDNSName(tags["s"]) || !validDNSName(tags["d"]) {
		return dkim.ResultPermError, "ARC-Seal d= or s= is not a DNS name in A-label form"
	}

	base := arcSealBase(chain)

	sigBytes, err := base64.StdEncoding.DecodeString(dkim.StripWSP(tags["b"]))
	if err != nil {
		return dkim.ResultPermError, "invalid ARC-Seal b= base64"
	}
	// The seal is constrained to rsa-sha256 (checked above), so the key is fetched
	// with hashAlg "sha256". Deliberately IGNORE the returned KeyFlags for the
	// seal: t=s constrains an AUID i=, but an ARC-Seal's i= is the instance
	// number, and s= service-type is a DKIM email-signature rule RFC 8617 does not
	// direct the seal to reject on — honouring either would newly fail chains that
	// verified before.
	pub, _, kres := dkim.FetchKey(ctx, tags["s"], tags["d"], "sha256", resolver)
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

// amsSignsFrom reports whether an ARC-Message-Signature h= tag list names the
// From header, as RFC 6376 §5.4 requires of the DKIM-Signature whose semantics
// the AMS has (RFC 8617 §4.1.2). The h= value is a
// colon-separated list of signed header field names; the match is on a whole
// entry (after trimming folding whitespace) and case-insensitive, so "from" or
// "From" counts but a different header whose name merely contains "from" (e.g.
// "x-from") does not. An empty or From-less h= returns false — the AMS does not
// cover the author identity and the chain must not verify.
func amsSignsFrom(hTag string) bool {
	for _, name := range strings.Split(hTag, ":") {
		if strings.EqualFold(trimFWS(name), "from") {
			return true
		}
	}
	return false
}

// amsSignsARC returns the first ARC-Seal or ARC-Message-Signature an
// ARC-Message-Signature h= tag list names, or "" if it names neither. RFC 8617
// §4.1.2 says the AMS MUST NOT cover the ARC header fields.
// ARC-Authentication-Results is not reported: draft-era sealers, and the
// ValiMail ARC test suite, sign it.
func amsSignsARC(hTag string) string {
	for _, name := range strings.Split(hTag, ":") {
		name = strings.ToLower(trimFWS(name))
		if name == "arc-seal" || name == "arc-message-signature" {
			return name
		}
	}
	return ""
}

// collectARCSets parses a header block's ARC fields into per-instance sets,
// keyed by their i= tag. It enforces RFC 8617 §4.2.1 / §5.2 step 3A: a valid ARC
// set contains exactly one each of ARC-Authentication-Results,
// ARC-Message-Signature, and ARC-Seal. A second field of the same type at the
// same instance makes that set — and the whole chain — malformed, so
// collectARCSets returns an error naming the instance and field rather than
// letting a later copy overwrite an earlier one. Silently keeping "last wins"
// (or "first wins") is a parser-differential: two verifiers can select different
// copies and reach different verdicts over the same bytes. Callers treat the
// error as chain-validation "fail".
func collectARCSets(headers []dkim.Header) (map[int]*arcSet, error) {
	sets := map[int]*arcSet{}
	for idx := range headers {
		h := &headers[idx]
		name := strings.ToLower(h.Name)
		if !isARCField(name) {
			continue
		}
		// This IS an ARC header field. From here any structural defect fails the
		// whole collection — chain status "fail" for Verify — rather than being
		// silently skipped: a field named ARC-* but carrying a malformed i= or
		// tag-list means the message bears a BROKEN chain, not none (RFC 8617
		// §5.2).
		i, err := fieldInstance(name, h.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", h.Name, err)
		}
		if sets[i] == nil {
			sets[i] = &arcSet{}
		}
		s := sets[i]
		switch name {
		case "arc-authentication-results":
			if s.aar != nil {
				return nil, fmt.Errorf("i=%d duplicate ARC-Authentication-Results", i)
			}
			s.aar = h
		case "arc-message-signature":
			if s.ams != nil {
				return nil, fmt.Errorf("i=%d duplicate ARC-Message-Signature", i)
			}
			// RFC 8617 §4.1.2: an ARC-Message-Signature has DKIM-Signature syntax
			// but the v= tag is not part of it. Strip any (unexpected) v= now, so
			// that both the AMS signature check and the ARC-Seal chain that covers
			// the AMS treat it as the versionless signature it is. See
			// stripAMSVersionTag.
			s.ams = stripAMSVersionTag(h)
		default:
			if s.as != nil {
				return nil, fmt.Errorf("i=%d duplicate ARC-Seal", i)
			}
			s.as = h
		}
	}
	return sets, nil
}

// isARCField reports whether a lowercased header field name is one of the
// three ARC header fields (RFC 8617 §4.1).
func isARCField(name string) bool {
	return name == "arc-authentication-results" || name == "arc-message-signature" || name == "arc-seal"
}

// fieldInstance returns the instance of an ARC header field, given its
// lowercased name and its value, or an error naming the defect.
//
// The ARC-Message-Signature and ARC-Seal are DKIM tag-lists (RFC 8617 §4.1.2,
// §4.1.3, importing RFC 6376 §3.2), read strictly: a tag name outside the
// ABNF, a repeated tag, or an empty tag-spec (";;") makes the field malformed,
// rather than taking one reading of it that another verifier might not share.
// Tag names are case-sensitive, so the instance is the i= tag; I= is an
// unknown tag. The i= tag may appear anywhere in the list, as it does in the
// fields many sealers write.
//
// The ARC-Authentication-Results is not a tag-list: RFC 8617 §4.1.1 defines it
// as arc-info = instance [CFWS] ";" authres-payload, so the i= tag comes first,
// with comments allowed around its parts, and a ";" follows it. The payload's syntax does not affect the chain
// (§3.4), so it is not parsed; its methods legally repeat.
func fieldInstance(name, value string) (int, error) {
	if name == "arc-authentication-results" {
		return aarInstance(value)
	}
	tags, err := strictTagList(value)
	if err != nil {
		return 0, err
	}
	raw, ok := tags["i"]
	if !ok {
		return 0, fmt.Errorf("missing required i= instance tag")
	}
	return parseInstance(raw)
}

// aarInstance reads the instance at the start of an ARC-Authentication-Results
// value by RFC 8617 §4.1.1 and §3.9:
//
//	arc-info = instance [CFWS] ";" authres-payload
//	instance = [CFWS] %s"i" [CFWS] "=" [CFWS] position
//
// CFWS is RFC 5322 §3.2.2 folding whitespace and comments, which may nest and
// hold quoted-pairs, so "i=1 (first hop);" and "(x) i (y)= 1;" are the
// instance 1.
func aarInstance(value string) (int, error) {
	missing := fmt.Errorf("missing required i= instance tag at the start of the field")
	rest, err := skipCFWS(value)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(rest, "i") {
		return 0, missing
	}
	if rest, err = skipCFWS(rest[1:]); err != nil {
		return 0, err
	}
	if !strings.HasPrefix(rest, "=") {
		return 0, missing
	}
	if rest, err = skipCFWS(rest[1:]); err != nil {
		return 0, err
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	digits := rest[:end]
	if rest, err = skipCFWS(rest[end:]); err != nil {
		return 0, err
	}
	if !strings.HasPrefix(rest, ";") {
		if rest != "" {
			return 0, fmt.Errorf("malformed i= instance %q (want a 1..%d decimal with no sign or leading zero)", digits+rest, maxInstance)
		}
		return 0, fmt.Errorf("no \";\" after the i= instance tag")
	}
	return parseInstance(digits)
}

// skipCFWS returns s without its leading CFWS (RFC 5322 §3.2.2): folding
// whitespace and comments, which nest and may hold quoted-pairs. A comment
// that is not closed is an error.
func skipCFWS(s string) (string, error) {
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		if !strings.HasPrefix(s, "(") {
			return s, nil
		}
		depth, i := 0, 0
		for ; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++ // quoted-pair: the next character is literal
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if depth != 0 {
			return "", fmt.Errorf("unclosed comment before the i= instance")
		}
		s = s[i+1:]
	}
}

// trimFWS removes the folding whitespace RFC 5322 §3.2.2 allows around a tag,
// a value or an h= entry (SP, HTAB, CR and LF), and nothing else.
// strings.TrimSpace would also strip form feeds and Unicode spaces, which the
// ABNF doesn't allow there.
func trimFWS(s string) string { return strings.Trim(s, " \t\r\n") }

// strictTagList parses a DKIM tag-list as dkim.ParseTagListStrict does (tag
// names and values by the RFC 6376 §3.2 ABNF, no repeated tag) and also
// refuses an empty tag-spec, which the ABNF allows only as the one optional
// ";" at the end.
func strictTagList(value string) (map[string]string, error) {
	tags, err := dkim.ParseTagListStrict(value)
	if err != nil {
		return nil, err
	}
	segs := strings.Split(value, ";")
	for _, seg := range segs[:len(segs)-1] {
		if trimFWS(seg) == "" {
			return nil, fmt.Errorf("empty tag-spec in tag-list")
		}
	}
	return tags, nil
}

// maxInstance is the RFC 8617 §4.2.1 ceiling on an individual ARC set's
// instance number: i ranges over 1..50. It equals maxARCSets — a contiguous
// chain's highest instance is its set count — but names the per-set range
// constraint parseInstance enforces, distinct from the chain-length ceiling
// Verify checks.
const maxInstance = maxARCSets

// parseInstance validates the value of an i= instance tag. A conformant
// instance is a bare decimal in 1..50 (RFC 8617 §3.9 "position = 1*2DIGIT",
// §4.2.1 range): no sign, no leading zero, no surrounding cruft, no overflow.
// It returns the instance on success, or an error naming the defect.
func parseInstance(raw string) (int, error) {
	if !validInstanceDigits(raw) {
		return 0, fmt.Errorf("malformed i= instance %q (want a 1..%d decimal with no sign or leading zero)", raw, maxInstance)
	}
	n, _ := strconv.Atoi(raw) // one or two digits: cannot fail
	if n > maxInstance {
		return 0, fmt.Errorf("i= instance %q out of range 1..%d", raw, maxInstance)
	}
	return n, nil
}

// validInstanceDigits reports whether s is the canonical decimal form of an ARC
// instance: 1 or 2 ASCII digits with no leading zero (RFC 8617 §3.9
// "position = 1*2DIGIT", canonical). It rejects "" , "007"/"01" (zero-padded or
// >2 digits), "0", "-3", "+1", "1 ", "1a", and any overflow, so only 1..99 in
// canonical form pass here; parseInstance additionally enforces the 1..50 range.
func validInstanceDigits(s string) bool {
	if len(s) < 1 || len(s) > 2 {
		return false
	}
	if s[0] < '1' || s[0] > '9' { // first digit non-zero: no leading zero, no sign
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validDNSName reports whether name is a DNS name in A-label form: dot-separated
// labels of 1 to 63 letters, digits, hyphens or underscores, 253 characters at
// most. It is the rule go-dkim applies to the d= and s= of a DKIM-Signature
// (and so of an AMS); go-arc applies it to the ARC-Seal and to what Seal
// writes.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// stripAMSVersionTag returns a copy of an ARC-Message-Signature header with any
// v= tag removed. RFC 8617 §4.1.2 defines the AMS with DKIM-Signature syntax but
// without a v= tag: unlike a DKIM-Signature, the AMS is not versioned. A
// conformant signer emits none, but an errant v= (e.g. v=DKIM1 copied from DKIM
// code, or added in transit) would otherwise trip the DKIM version rule
// (RFC 6376 §3.5, which rejects any v= not equal to 1) when the AMS is verified
// through go-dkim — failing the entire chain over a tag the RFC says is not part
// of the signature. Removing it here, at the single point Verify and Seal both
// collect ARC sets, makes an unexpected v= ignored rather than fatal, and keeps
// the AMS byte-identical to its versionless form for BOTH the AMS signature check
// AND the ARC-Seal that covers the AMS field. Every other byte is preserved, so a
// genuinely broken chain (bad body hash, tampered header, forged signature) still
// fails.
func stripAMSVersionTag(h *dkim.Header) *dkim.Header {
	out := *h
	out.Value = removeVTag(h.Value)
	out.Raw = removeVTag(h.Raw)
	return &out
}

// removeVTag deletes the entire v= tag — its name, value, and trailing
// delimiter — from a signature field, preserving every other byte. It differs
// from dkim.RemoveBValue, which blanks only a value while keeping the "b=" shell:
// the AMS must read as if no v= tag were ever present (RFC 8617 §4.1.2), so the
// whole tag is dropped. The v= tag is never the final tag of an AMS (b= is), so
// dropping its delimiter never leaves a dangling trailing ";".
func removeVTag(field string) string {
	var b strings.Builder
	i, n := 0, len(field)
	for i < n {
		seg := field[i:]
		hasDelim := false
		if j := strings.IndexByte(field[i:], ';'); j >= 0 {
			seg = field[i : i+j]
			i += j + 1
			hasDelim = true
		} else {
			i = n
		}
		if eq := strings.IndexByte(seg, '='); eq >= 0 && trimFWS(seg[:eq]) == "v" {
			continue // drop the whole v= tag together with its delimiter
		}
		b.WriteString(seg)
		if hasDelim {
			b.WriteByte(';')
		}
	}
	return b.String()
}
