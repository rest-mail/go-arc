package arc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim"
)

// --- test-side ARC sealer (constructs valid ARC sets to verify against) ---

func arcBaseMessage() string {
	return strings.Join([]string{
		`From: "Alice" <alice@example.test>`,
		"To: bob@rcpt.test",
		"Subject: arc round trip",
		"Date: Thu, 23 Jul 2026 03:01:40 +0000",
		"Message-ID: <arc-1@example.test>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"ARC body.\r\n",
	}, "\r\n")
}

// signAMS builds an ARC-Message-Signature value (DKIM-style) over msgHeaders+body.
func signAMS(t *testing.T, priv *rsa.PrivateKey, d, s string, i int, msgHeaders []dkim.Header, body string) string {
	t.Helper()
	bodyHash := dkim.HashBytes(crypto.SHA256, []byte(dkim.CanonicalizeBody(body, "relaxed")))
	bh := base64.StdEncoding.EncodeToString(bodyHash)
	hTag := "from:to:subject:date:message-id"
	valueNoB := fmt.Sprintf("i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=", i, d, s, hTag, bh)
	sigHeader := dkim.Header{Name: "ARC-Message-Signature", Value: " " + valueNoB, Raw: "ARC-Message-Signature: " + valueNoB}
	signed := dkim.BuildSignedHeaders(hTag, msgHeaders, sigHeader, "relaxed")
	hashed := dkim.HashBytes(crypto.SHA256, []byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	return valueNoB + base64.StdEncoding.EncodeToString(sig)
}

// signAS builds an ARC-Seal value over the chain (ascending), sealing the last set.
func signAS(t *testing.T, priv *rsa.PrivateKey, d, s string, i int, cv string, chain []*arcSet) string {
	t.Helper()
	valueNoB := fmt.Sprintf("i=%d; a=rsa-sha256; d=%s; s=%s; t=1784776000; cv=%s; b=", i, d, s, cv)
	seal := &dkim.Header{Name: "ARC-Seal", Value: " " + valueNoB, Raw: "ARC-Seal: " + valueNoB}
	chain[len(chain)-1].as = seal
	base := arcSealBase(chain)
	hashed := dkim.HashBytes(crypto.SHA256, []byte(base))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	return valueNoB + base64.StdEncoding.EncodeToString(sig)
}

func mkHeader(name, value string) *dkim.Header {
	return &dkim.Header{Name: name, Value: " " + value, Raw: name + ": " + value}
}

// sealChain builds an N-instance ARC-sealed message over base and returns the raw.
func sealChain(t *testing.T, priv *rsa.PrivateKey, d, s string, n int) string {
	t.Helper()
	cvs := make([]string, n)
	for i := range cvs {
		cvs[i] = "pass"
	}
	cvs[0] = "none"
	return sealChainCV(t, priv, d, s, cvs)
}

// sealChainCV builds an ARC-sealed message like sealChain but stamps each set's
// ARC-Seal with the caller-supplied cv= value (cvs[i-1]). Every seal signature
// is still cryptographically valid over the bytes it signs — including whatever
// cv= it carries — so a test can forge a chain whose cv= tags are internally
// inconsistent (e.g. cv=fail, or cv=pass at i=1) yet cryptographically intact.
func sealChainCV(t *testing.T, priv *rsa.PrivateKey, d, s string, cvs []string) string {
	t.Helper()
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))

	var prepend strings.Builder
	chain := []*arcSet{}
	for i := 1; i <= len(cvs); i++ {
		aar := mkHeader("ARC-Authentication-Results", fmt.Sprintf("i=%d; example.test; spf=pass", i))
		ams := mkHeader("ARC-Message-Signature", signAMS(t, priv, d, s, i, msgHeaders, body))
		set := &arcSet{aar: aar, ams: ams}
		chain = append(chain, set)
		set.as = mkHeader("ARC-Seal", signAS(t, priv, d, s, i, cvs[i-1], chain))

		// ARC sets are prepended in reverse (highest instance on top).
		block := set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n"
		prepend.WriteString(block)
	}
	return prepend.String() + base
}

// testKeyResolver returns a dkim.TXTResolver that serves priv's public key at
// <selector>._domainkey.<domain> and NXDOMAIN for everything else.
func testKeyResolver(t *testing.T, pubPEM, selector, domain string) dkim.TXTResolver {
	t.Helper()
	txt, err := dkim.RecordValue(pubPEM)
	if err != nil {
		t.Fatalf("RecordValue: %v", err)
	}
	want := dkim.RecordName(selector, domain)
	return func(_ context.Context, name string) ([]string, error) {
		if name == want {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

// publicPEM renders a private key's public half exactly as dkim.GenerateKey does
// (PKIX SubjectPublicKeyInfo), which is what dkim.RecordValue consumes.
func publicPEM(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// --- tests ---

func TestVerifyARC_SingleSetRoundTrip(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)

	cv, reason := Verify(context.Background(), []byte(raw), resolver)
	if cv != "pass" {
		t.Fatalf("want pass, got %s (%s)", cv, reason)
	}
}

func TestVerifyARC_TwoSetChain(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 2)

	cv, reason := Verify(context.Background(), []byte(raw), resolver)
	if cv != "pass" {
		t.Fatalf("want pass for 2-set chain, got %s (%s)", cv, reason)
	}
}

func TestVerifyARC_TamperedBodyFailsAMS(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)
	tampered := strings.Replace(raw, "ARC body.", "TAMPERED.", 1)

	cv, reason := Verify(context.Background(), []byte(tampered), resolver)
	if cv != "fail" {
		t.Fatalf("want fail on body tamper, got %s (%s)", cv, reason)
	}
	if !strings.Contains(reason, "ARC-Message-Signature") {
		t.Errorf("expected AMS failure, got: %s", reason)
	}
}

func TestVerifyARC_TamperedSealFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)
	// Tamper the signed ARC-Authentication-Results (covered by the seal, not AMS).
	tampered := strings.Replace(raw, "spf=pass", "spf=fail", 1)

	cv, reason := Verify(context.Background(), []byte(tampered), resolver)
	if cv != "fail" {
		t.Fatalf("want fail on AAR tamper, got %s (%s)", cv, reason)
	}
	if !strings.Contains(reason, "ARC-Seal") {
		t.Errorf("expected ARC-Seal failure, got: %s", reason)
	}
}

// TestVerifyARC_AMSVersionTagIgnored covers RFC 8617 §4.1.2: an
// ARC-Message-Signature has DKIM-Signature syntax but the v= tag is not part of
// it. A conformant AMS carries no v=, but an errant one (e.g. v=DKIM1 copied from
// DKIM code, or inserted in transit) must be IGNORED, not fail the whole chain.
// Here a fully valid single-set chain is sealed (AMS and ARC-Seal signed over the
// AMS's real, v=-free bytes), then an unexpected v=DKIM1 is injected into the
// transmitted AMS. Verify must still report "pass": the DKIM version rule
// (RFC 6376 §3.5, which rejects v= not equal to 1) must not be applied to the
// AMS. Before the fix, Verify delegated AMS verification straight to
// dkim.VerifySignature, whose version rule rejected v=DKIM1 and failed the chain.
func TestVerifyARC_AMSVersionTagIgnored(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)

	// Inject an unexpected v= into the transmitted AMS as a clean tag (RFC 8617
	// says it is not part of the AMS, so a verifier strips it before checking).
	withV := strings.Replace(raw,
		"ARC-Message-Signature: i=1; ",
		"ARC-Message-Signature: i=1; v=DKIM1; ", 1)
	if withV == raw {
		t.Fatal("test setup: failed to inject v= into the ARC-Message-Signature")
	}

	cv, reason := Verify(context.Background(), []byte(withV), resolver)
	if cv != "pass" {
		t.Fatalf("AMS with an unexpected v= must be ignored (still pass), got %s (%s)", cv, reason)
	}
}

// TestVerifyARC_AMSVersionTagStillFailsOnTamper is the malformed counterpart: an
// unexpected v= on the AMS is ignored, but ignoring it must not mask a real
// breakage. A chain whose body is tampered must still fail even when the AMS also
// carries a v= tag — the AMS signature verification (over every byte but the
// stripped v=) still runs.
func TestVerifyARC_AMSVersionTagStillFailsOnTamper(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)
	withV := strings.Replace(raw,
		"ARC-Message-Signature: i=1; ",
		"ARC-Message-Signature: i=1; v=DKIM1; ", 1)
	tampered := strings.Replace(withV, "ARC body.", "TAMPERED.", 1)

	cv, reason := Verify(context.Background(), []byte(tampered), resolver)
	if cv != "fail" {
		t.Fatalf("tampered body must fail even with an unexpected AMS v=, got %s (%s)", cv, reason)
	}
	if !strings.Contains(reason, "ARC-Message-Signature") {
		t.Errorf("expected an AMS failure reason, got: %s", reason)
	}
}

func TestVerifyARC_NoChain(t *testing.T) {
	cv, _ := Verify(context.Background(), []byte("From: a@b.test\r\nSubject: x\r\n\r\nbody\r\n"),
		func(context.Context, string) ([]string, error) { return nil, nil })
	if cv != "none" {
		t.Errorf("want none, got %s", cv)
	}
}

// TestVerifyARC_InconsistentCV covers RFC 8617 §5.2 steps 2 & 3C: an ARC-Seal's
// cv= tag must be "none" at i=1 and "pass" at every i>1. A chain whose cv= is
// inconsistent — even with every signature cryptographically intact — describes
// a chain the RFC says can never be continued, so it must verify as "fail". A
// verifier that trusts the asserted cv= would launder a broken chain.
func TestVerifyARC_InconsistentCV(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	cases := []struct {
		name string
		cvs  []string
	}{
		{"i1_says_pass", []string{"pass"}},         // i=1 must be cv=none
		{"i1_says_fail", []string{"fail"}},         // cv=fail can never be continued
		{"i1_missing", []string{""}},               // absent cv= is not a valid assertion
		{"i2_says_none", []string{"none", "none"}}, // i>1 must be cv=pass
		{"i2_says_fail", []string{"none", "fail"}}, // highest-instance cv=fail => chain fail
		{"i2_bogus", []string{"none", "bogus"}},    // unknown cv= => chain fail
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := sealChainCV(t, priv, "example.test", "arc", tc.cvs)
			cv, reason := Verify(context.Background(), []byte(raw), resolver)
			if cv != "fail" {
				t.Fatalf("cvs=%v: want fail on inconsistent cv=, got %s (%s)", tc.cvs, cv, reason)
			}
		})
	}
}

func TestVerifyARC_WrongKeyFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	other, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := sealChain(t, priv, "example.test", "arc", 1)
	cv, _ := Verify(context.Background(), []byte(raw), testKeyResolver(t, publicPEM(t, other), "arc", "example.test"))
	if cv != "fail" {
		t.Errorf("want fail with wrong key, got %s", cv)
	}
}

// duplicateFirstHeader returns raw with a verbatim copy of its first field named
// name inserted immediately after the original, giving the message two of that
// ARC field at the same instance.
func duplicateFirstHeader(t *testing.T, raw, name string) string {
	t.Helper()
	pieces := strings.SplitAfter(raw, "\r\n") // keep CRLF terminators attached
	for i, ln := range pieces {
		if strings.HasPrefix(ln, name+":") {
			out := make([]string, 0, len(pieces)+1)
			out = append(out, pieces[:i+1]...)
			out = append(out, ln)
			out = append(out, pieces[i+1:]...)
			return strings.Join(out, "")
		}
	}
	t.Fatalf("header %q not found in message", name)
	return ""
}

// TestVerifyARC_DuplicateFieldRejected covers RFC 8617 §5.1.1 / §5.2 step 3A: a
// valid ARC set contains exactly one each of the three ARC header fields. A
// second copy of any field at the same instance makes the set — and the chain —
// malformed, so Verify must return "fail". A verifier that keeps "last wins"
// silently accepts the extra copy (whose bytes are identical here, so every
// signature still verifies) and reports "pass", a parser-differential an
// attacker can exploit against verifiers that instead keep the first copy.
func TestVerifyARC_DuplicateFieldRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	for _, name := range []string{"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
		t.Run(name, func(t *testing.T) {
			raw := sealChain(t, priv, "example.test", "arc", 1)
			dup := duplicateFirstHeader(t, raw, name)

			cv, reason := Verify(context.Background(), []byte(dup), resolver)
			if cv != "fail" {
				t.Fatalf("want fail on duplicate %s, got %s (%s)", name, cv, reason)
			}
			if !strings.Contains(reason, "duplicate") {
				t.Errorf("expected a duplicate-field reason, got: %s", reason)
			}
		})
	}
}
