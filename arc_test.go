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
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))

	var prepend strings.Builder
	chain := []*arcSet{}
	for i := 1; i <= n; i++ {
		cv := "pass"
		if i == 1 {
			cv = "none"
		}
		aar := mkHeader("ARC-Authentication-Results", fmt.Sprintf("i=%d; example.test; spf=pass", i))
		ams := mkHeader("ARC-Message-Signature", signAMS(t, priv, d, s, i, msgHeaders, body))
		set := &arcSet{aar: aar, ams: ams}
		chain = append(chain, set)
		set.as = mkHeader("ARC-Seal", signAS(t, priv, d, s, i, cv, chain))

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

func TestVerifyARC_NoChain(t *testing.T) {
	cv, _ := Verify(context.Background(), []byte("From: a@b.test\r\nSubject: x\r\n\r\nbody\r\n"),
		func(context.Context, string) ([]string, error) { return nil, nil })
	if cv != "none" {
		t.Errorf("want none, got %s", cv)
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
