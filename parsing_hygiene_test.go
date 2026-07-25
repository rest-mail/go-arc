package arc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim"
)

// --- helpers for issue #17 (parsing + output hygiene) ---

// signBase64 signs data with priv (rsa-sha256) and returns the base64 signature,
// failing the test on error. It is the test-side counterpart to seal.go's
// signRSA, used by the literal-instance / duplicate-tag builders below.
func signBase64(t *testing.T, priv *rsa.PrivateKey, data string) string {
	t.Helper()
	sig, err := signRSA(priv, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// rawSingleInstance builds a message whose ONLY ARC content is a single set
// (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results) all stamped with
// the literal instance iLit and dummy signatures. It is used to prove how a
// malformed i= is classified: with no other ARC set present, a verifier that
// SKIPS the malformed set (treating it as "not an ARC header") reports "none",
// whereas one that recognizes it as a malformed ARC field reports "fail". No
// valid signatures are needed because both outcomes are decided before any
// cryptography.
func rawSingleInstance(iLit string) string {
	as := fmt.Sprintf("ARC-Seal: i=%s; a=rsa-sha256; d=example.test; s=arc; cv=none; b=AAAA", iLit)
	ams := fmt.Sprintf("ARC-Message-Signature: i=%s; a=rsa-sha256; c=relaxed/relaxed; d=example.test; s=arc; h=from; bh=AAAA; b=AAAA", iLit)
	aar := fmt.Sprintf("ARC-Authentication-Results: i=%s; example.test; spf=pass", iLit)
	return as + "\r\n" + ams + "\r\n" + aar + "\r\n" + arcBaseMessage()
}

// sealSingleLiteralInstance builds a cryptographically intact single-set ARC
// message whose three fields carry the LITERAL instance string iLit (e.g. "1" or
// the zero-padded "01"), signing every signature over exactly those bytes. It
// isolates instance-format validation: a chain sealed over "i=01" verifies
// cryptographically, so only an explicit format check can reject it.
func sealSingleLiteralInstance(t *testing.T, priv *rsa.PrivateKey, d, s, iLit string) string {
	t.Helper()
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))

	bh := base64.StdEncoding.EncodeToString(dkim.HashBytes(crypto.SHA256, []byte(dkim.CanonicalizeBody(body, "relaxed"))))
	hTag := "from:to:subject:date:message-id"
	amsNoB := fmt.Sprintf("i=%s; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=", iLit, d, s, hTag, bh)
	amsHdr := dkim.Header{Name: "ARC-Message-Signature", Value: " " + amsNoB, Raw: "ARC-Message-Signature: " + amsNoB}
	amsSig := signBase64(t, priv, dkim.BuildSignedHeaders(hTag, msgHeaders, amsHdr, "relaxed"))
	ams := mkHeader("ARC-Message-Signature", amsNoB+amsSig)
	aar := mkHeader("ARC-Authentication-Results", fmt.Sprintf("i=%s; example.test; spf=pass", iLit))

	set := &arcSet{aar: aar, ams: ams}
	chain := []*arcSet{set}
	asNoB := fmt.Sprintf("i=%s; a=rsa-sha256; d=%s; s=%s; t=1784776000; cv=none; b=", iLit, d, s)
	set.as = mkHeader("ARC-Seal", asNoB)
	asSig := signBase64(t, priv, arcSealBase(chain))
	set.as = mkHeader("ARC-Seal", asNoB+asSig)

	return set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n" + base
}

// sealSingleDupSealTag builds a valid single-set ARC message whose ARC-Seal
// carries a DUPLICATED tag (cv=none twice), signed over the exact duplicated
// bytes so the seal signature verifies. The only defect is the repeated tag,
// which RFC 6376 §3.2 says invalidates the whole tag list.
func sealSingleDupSealTag(t *testing.T, priv *rsa.PrivateKey, d, s string) string {
	t.Helper()
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))
	ams := mkHeader("ARC-Message-Signature", signAMS(t, priv, d, s, 1, msgHeaders, body))
	aar := mkHeader("ARC-Authentication-Results", "i=1; example.test; spf=pass")

	set := &arcSet{aar: aar, ams: ams}
	chain := []*arcSet{set}
	asNoB := fmt.Sprintf("i=1; a=rsa-sha256; d=%s; s=%s; t=1784776000; cv=none; cv=none; b=", d, s)
	set.as = mkHeader("ARC-Seal", asNoB)
	asSig := signBase64(t, priv, arcSealBase(chain))
	set.as = mkHeader("ARC-Seal", asNoB+asSig)

	return set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n" + base
}

// sealSingleDupAMSTag builds a valid single-set ARC message whose
// ARC-Message-Signature carries a DUPLICATED tag (c= twice), signed over exactly
// those bytes so the AMS signature verifies. As with the seal, the only defect
// is the repeated tag (RFC 6376 §3.2).
func sealSingleDupAMSTag(t *testing.T, priv *rsa.PrivateKey, d, s string) string {
	t.Helper()
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))

	bh := base64.StdEncoding.EncodeToString(dkim.HashBytes(crypto.SHA256, []byte(dkim.CanonicalizeBody(body, "relaxed"))))
	hTag := "from:to:subject:date:message-id"
	amsNoB := fmt.Sprintf("i=1; a=rsa-sha256; c=relaxed/relaxed; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=", d, s, hTag, bh)
	amsHdr := dkim.Header{Name: "ARC-Message-Signature", Value: " " + amsNoB, Raw: "ARC-Message-Signature: " + amsNoB}
	amsSig := signBase64(t, priv, dkim.BuildSignedHeaders(hTag, msgHeaders, amsHdr, "relaxed"))
	ams := mkHeader("ARC-Message-Signature", amsNoB+amsSig)
	aar := mkHeader("ARC-Authentication-Results", "i=1; example.test; spf=pass")

	set := &arcSet{aar: aar, ams: ams}
	chain := []*arcSet{set}
	asNoB := fmt.Sprintf("i=1; a=rsa-sha256; d=%s; s=%s; t=1784776000; cv=none; b=", d, s)
	set.as = mkHeader("ARC-Seal", asNoB)
	asSig := signBase64(t, priv, arcSealBase(chain))
	set.as = mkHeader("ARC-Seal", asNoB+asSig)

	return set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n" + base
}

// --- sub-item 1: instance-number validation on the verify path ---

// TestVerifyARC_MalformedInstanceFailsNotNone covers the headline of issue #17:
// an ARC field whose i= is unparseable, zero, negative, or overflowing must fail
// the chain, NOT be silently demoted. The old arcInstance used strconv.Atoi and
// mapped i=0, i=-3, and an overflowing i=99999999999999999999 all to 0; the set
// was then dropped (i<1 treated as "not an ARC header"), so a message that
// plainly carries ARC returned "none" instead of "fail". Each message here has a
// single ARC set with the given malformed instance and nothing else, so the old
// path returned "none" (confirmed RED); the fix reports "fail".
func TestVerifyARC_MalformedInstanceFailsNotNone(t *testing.T) {
	stub := func(context.Context, string) ([]string, error) { return nil, nil }
	for _, iLit := range []string{"0", "-3", "99999999999999999999"} {
		t.Run("i="+iLit, func(t *testing.T) {
			cv, reason := Verify(context.Background(), []byte(rawSingleInstance(iLit)), stub)
			if cv != "fail" {
				t.Fatalf("a malformed i=%s ARC set must fail the chain, got %s (%s)", iLit, cv, reason)
			}
			if !strings.Contains(reason, "instance") && !strings.Contains(reason, "i=") {
				t.Errorf("expected an instance-validation reason, got: %s", reason)
			}
		})
	}
}

// TestVerifyARC_OutOfRangeInstanceRejected covers the RFC 8617 §5.1.1 range:
// an instance must lie in 1..50. A lone in-range-but-non-contiguous instance was
// already caught by the contiguity check, but an out-of-range value must be
// rejected as a malformed instance regardless of position.
func TestVerifyARC_OutOfRangeInstanceRejected(t *testing.T) {
	stub := func(context.Context, string) ([]string, error) { return nil, nil }
	for _, iLit := range []string{"51", "99"} {
		t.Run("i="+iLit, func(t *testing.T) {
			cv, reason := Verify(context.Background(), []byte(rawSingleInstance(iLit)), stub)
			if cv != "fail" {
				t.Fatalf("out-of-range i=%s must fail the chain, got %s (%s)", iLit, cv, reason)
			}
		})
	}
}

// TestVerifyARC_ZeroPaddedInstanceRejected covers RFC 8617 §4.1.1
// (instance = 1*2DIGIT, canonical form): a zero-padded i=01 is a distinct byte
// string that the old strconv.Atoi path folded to instance 1. Signed over its
// literal bytes such a chain verifies cryptographically, so the old code
// accepted it ("pass") — a parser-differential, since another verifier might
// reject or renumber it. It must fail. A canonical i=1 control still passes.
func TestVerifyARC_ZeroPaddedInstanceRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	if cv, reason := Verify(context.Background(),
		[]byte(sealSingleLiteralInstance(t, priv, "example.test", "arc", "1")), resolver); cv != "pass" {
		t.Fatalf("canonical i=1 control must pass, got %s (%s)", cv, reason)
	}

	for _, iLit := range []string{"01", "07"} {
		t.Run("i="+iLit, func(t *testing.T) {
			raw := sealSingleLiteralInstance(t, priv, "example.test", "arc", iLit)
			cv, reason := Verify(context.Background(), []byte(raw), resolver)
			if cv != "fail" {
				t.Fatalf("zero-padded i=%s must fail the chain, got %s (%s)", iLit, cv, reason)
			}
			if !strings.Contains(reason, "instance") && !strings.Contains(reason, "i=") {
				t.Errorf("expected an instance-format reason, got: %s", reason)
			}
		})
	}
}

// --- sub-item 2: duplicate tags within an ARC-Message-Signature / ARC-Seal ---

// TestVerifyARC_DuplicateTagRejected covers RFC 6376 §3.2: a DKIM tag list with a
// repeated tag name is invalid. The ARC-Message-Signature and ARC-Seal are DKIM
// tag lists, so a duplicate tag in either must fail the chain. The old code took
// dkim.ParseTagList's last-wins value and, because each field is signed over its
// own duplicated bytes, verified the chain as "pass" — a parser-differential
// another verifier (first-wins, or reject) would score differently. Confirmed
// RED (pass) before the fix; fail after.
func TestVerifyARC_DuplicateTagRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	cases := []struct {
		name  string
		build func() string
	}{
		{"ARC-Seal", func() string { return sealSingleDupSealTag(t, priv, "example.test", "arc") }},
		{"ARC-Message-Signature", func() string { return sealSingleDupAMSTag(t, priv, "example.test", "arc") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cv, reason := Verify(context.Background(), []byte(tc.build()), resolver)
			if cv != "fail" {
				t.Fatalf("a duplicate tag in the %s must fail the chain, got %s (%s)", tc.name, cv, reason)
			}
			if !strings.Contains(reason, "duplicate") {
				t.Errorf("expected a duplicate-tag reason, got: %s", reason)
			}
		})
	}
}

// --- sub-item 3: CRLF sanitization of caller-supplied Seal inputs ---

// TestSeal_RejectsCRLFInjection covers header injection: Seal interpolates
// Domain, Selector, and AuthResults verbatim into emitted header field values, so
// a value carrying a bare CR or LF would fold additional header fields into the
// sealed message. The old code performed no sanitization and produced such a
// message (RED: no error); the fix rejects the input.
func TestSeal_RejectsCRLFInjection(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	newOpt := func() SealOptions {
		return SealOptions{
			Domain:      "example.test",
			Selector:    "arc",
			PrivateKey:  priv,
			AuthResults: "example.test; spf=pass",
			Resolver:    resolver,
			Time:        1784776000,
		}
	}

	cases := []struct {
		name   string
		mutate func(*SealOptions)
	}{
		{"AuthResults_CRLF", func(o *SealOptions) { o.AuthResults = "example.test; spf=pass\r\nInjected: evil" }},
		{"AuthResults_LF", func(o *SealOptions) { o.AuthResults = "example.test; spf=pass\nInjected: evil" }},
		{"Domain_CRLF", func(o *SealOptions) { o.Domain = "example.test\r\nInjected: evil" }},
		{"Selector_CR", func(o *SealOptions) { o.Selector = "arc\rInjected: evil" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opt := newOpt()
			tc.mutate(&opt)
			_, err := Seal(context.Background(), []byte(arcBaseMessage()), opt)
			if err == nil {
				t.Fatalf("Seal must reject a CR/LF-bearing input (%s) as header injection, got nil error", tc.name)
			}
			if !strings.Contains(err.Error(), "CR or LF") {
				t.Errorf("expected a header-injection error, got: %v", err)
			}
		})
	}
}

// --- sub-item 4: AMS h= must exclude ARC-* / Authentication-Results ---

// TestAMSHeaderTag_ExcludesARCAndAuthResults covers RFC 8617 §4.1.2: the
// ARC-Message-Signature h= tag MUST NOT list the ARC-* fields or
// Authentication-Results — fields the ARC set adds or that are hop-local and
// mutate in transit. The old amsHeaderTag included any requested header that was
// present, so a caller listing them (or sealing over an existing chain and
// requesting the prior ARC fields) signed fields that break downstream. The fix
// drops them from h= even when requested and present.
func TestAMSHeaderTag_ExcludesARCAndAuthResults(t *testing.T) {
	headers := []dkim.Header{
		{Name: "From", Value: " a@example.test"},
		{Name: "Subject", Value: " hi"},
		{Name: "Authentication-Results", Value: " mx.example.test; dkim=pass"},
		{Name: "ARC-Seal", Value: " i=1; a=rsa-sha256; cv=none; b=x"},
		{Name: "ARC-Message-Signature", Value: " i=1; a=rsa-sha256; b=x"},
		{Name: "ARC-Authentication-Results", Value: " i=1; example.test; spf=pass"},
	}
	want := []string{
		"from", "subject", "authentication-results",
		"arc-seal", "arc-message-signature", "arc-authentication-results",
	}
	got := amsHeaderTag(headers, want)
	if got != "from:subject" {
		t.Fatalf("AMS h= must be exactly the non-excluded present headers, got %q", got)
	}
	for _, bad := range []string{"arc-seal", "arc-message-signature", "arc-authentication-results", "authentication-results"} {
		if strings.Contains(got, bad) {
			t.Errorf("AMS h= must not list %q, got %q", bad, got)
		}
	}
}

// TestSeal_AMSHeaderTagExcludesInPractice confirms the exclusion end-to-end: a
// second hop sealing over an existing ARC chain, and explicitly requesting the
// prior ARC fields and Authentication-Results in Headers, must not emit them in
// the new ARC-Message-Signature's h= tag.
func TestSeal_AMSHeaderTagExcludesInPractice(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	// A message that already carries one ARC set plus an Authentication-Results.
	first := sealChain(t, priv, "example.test", "arc", 1)
	withAR := "Authentication-Results: mx.example.test; dkim=pass\r\n" + first

	res, err := Seal(context.Background(), []byte(withAR), SealOptions{
		Domain:     "example.test",
		Selector:   "arc",
		PrivateKey: priv,
		Headers: []string{
			"from", "authentication-results",
			"arc-seal", "arc-message-signature", "arc-authentication-results",
		},
		AuthResults: "example.test; arc=pass",
		Resolver:    resolver,
		Time:        1784776000,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	hTag := amsHTag(t, res.AMS)
	for _, bad := range []string{"arc-seal", "arc-message-signature", "arc-authentication-results", "authentication-results"} {
		if strings.Contains(hTag, bad) {
			t.Errorf("emitted AMS h= must not list %q, got h=%q", bad, hTag)
		}
	}
	if !strings.Contains(hTag, "from") {
		t.Errorf("emitted AMS h= should still list the requested present 'from', got h=%q", hTag)
	}
}

// amsHTag extracts the h= tag value from a rendered ARC-Message-Signature field.
func amsHTag(t *testing.T, amsField string) string {
	t.Helper()
	v := strings.TrimPrefix(amsField, "ARC-Message-Signature:")
	return dkim.ParseTagList(v)["h"]
}
