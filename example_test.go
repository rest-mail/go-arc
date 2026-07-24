package arc_test

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

// Example verifies an ARC-sealed message. Real ARC sets are added upstream by
// forwarders and mailing lists; go-arc only verifies them. To keep the round
// trip self-contained, sealARC below builds one valid ARC set from go-dkim's
// primitives, and an in-memory resolver serves the matching public key — in
// production you would pass nil for the resolver and let Verify use system DNS.
func Example() {
	// One keypair signs the ARC set here and answers the key lookup below. Keep
	// the private key for signing; publish the public half as the DNS TXT record.
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

	// Serve the public key we just generated from memory so the example needs no
	// real DNS. In production, pass nil to use the system resolver.
	txt, err := dkim.RecordValue(pubPEM)
	if err != nil {
		panic(err)
	}
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name == dkim.RecordName("arc", "example.com") {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no record for %s", name)
	}

	cv, reason := arc.Verify(context.Background(), sealed, resolver)
	fmt.Printf("%s: %s\n", cv, reason)
	// Output: pass: ARC chain cryptographically verified (1 set(s))
}

// sealARC prepends a single valid ARC set (instance 1) to raw, signed with priv
// for d=domain s=selector. It uses only go-dkim's exported primitives, mirroring
// what an ARC sealer at the first hop emits, so arc.Verify sees a genuine chain.
func sealARC(priv *rsa.PrivateKey, domain, selector string, raw []byte) []byte {
	headers, body := dkim.SplitMessage(raw)

	// ARC-Authentication-Results (i=1): the assessment this hop records.
	aar := dkim.Header{
		Name:  "ARC-Authentication-Results",
		Value: " i=1; " + domain + "; spf=pass",
		Raw:   "ARC-Authentication-Results: i=1; " + domain + "; spf=pass",
	}

	// ARC-Message-Signature (i=1): a DKIM-style signature over the message.
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

	// ARC-Seal (i=1): signs the relaxed-canonicalized AAR + AMS + AS chain, with
	// this seal's own b= empty and no trailing CRLF (RFC 8617 §5.1.1). cv=none
	// because this is the first hop.
	asNoB := fmt.Sprintf("i=1; a=rsa-sha256; d=%s; s=%s; cv=none; b=", domain, selector)
	asForSigning := dkim.Header{Name: "ARC-Seal", Value: " " + asNoB, Raw: "ARC-Seal: " + asNoB}
	sealBase := dkim.CanonicalizeHeader(aar, "relaxed") + "\r\n" +
		dkim.CanonicalizeHeader(ams, "relaxed") + "\r\n" +
		dkim.CanonicalizeHeader(asForSigning, "relaxed")
	asB := signRSA(priv, sealBase)
	as := dkim.Header{Name: "ARC-Seal", Raw: "ARC-Seal: " + asNoB + asB}

	// ARC sets are prepended highest-instance-first: seal, signature, then
	// authentication results, followed by the original message.
	return []byte(as.Raw + "\r\n" + ams.Raw + "\r\n" + aar.Raw + "\r\n" + string(raw))
}

func signRSA(priv *rsa.PrivateKey, data string) string {
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, dkim.HashBytes(crypto.SHA256, []byte(data)))
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// ExampleSeal seals a message the way a forwarder would, then verifies the
// result with arc.Verify — the round trip a downstream receiver relies on.
// Unlike Example above (which hand-rolls a set to exercise the verifier), this
// uses the public arc.Seal API end to end. An in-memory resolver serves the
// signing key; in production publish the public half as a DNS TXT record and
// pass nil for the resolver.
func ExampleSeal() {
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

	txt, err := dkim.RecordValue(pubPEM)
	if err != nil {
		panic(err)
	}
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name == dkim.RecordName("arc", "example.com") {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no record for %s", name)
	}

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

	cv, reason := arc.Verify(context.Background(), res.Message, resolver)
	fmt.Printf("sealed i=%d cv=%s -> verify %s: %s\n", res.Instance, res.ChainValidation, cv, reason)
	// Output: sealed i=1 cv=none -> verify pass: ARC chain cryptographically verified (1 set(s))
}
