package arc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

// TestSeal_SignsChangesMadeBeforeSealing walks the case ARC exists for: a
// mailing list receives a sealed message, validates it, rewrites the Subject
// and appends a footer, and only then seals (RFC 8617 §5.1 step 1). The list's
// own changes are covered by its ARC-Message-Signature, the ARC-Seal records
// the status the chain had on arrival, and a change made after sealing breaks
// the chain.
//
// checklist: ARC-HDR-06 ARC-SEAL-01
func TestSeal_SignsChangesMadeBeforeSealing(t *testing.T) {
	ctx := context.Background()
	origin, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	list, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := keyResolver(t,
		keyEntry{priv: origin, selector: "arc", domain: "origin.test"},
		keyEntry{priv: list, selector: "lists", domain: "list.test"})

	first, err := Seal(ctx, []byte(arcBaseMessage()), SealOptions{
		Domain: "origin.test", Selector: "arc", PrivateKey: origin,
		AuthResults: "origin.test; spf=pass", Resolver: resolver, Time: 1784776000,
	})
	if err != nil {
		t.Fatalf("first Seal: %v", err)
	}
	received := first.Message
	arrival, reason := Verify(ctx, received, resolver)
	if arrival != "pass" {
		t.Fatalf("chain on arrival: %s (%s)", arrival, reason)
	}

	// The list's modifications, made before it seals.
	modified := bytes.Replace(received, []byte("Subject: arc round trip"), []byte("Subject: [list] arc round trip"), 1)
	modified = append(modified, []byte("-- \r\nlist footer\r\n")...)
	if cv, _ := Verify(ctx, modified, resolver); cv != "fail" {
		t.Fatalf("the list's changes should break the first hop's AMS, got %s", cv)
	}

	second, err := Seal(ctx, modified, SealOptions{
		Domain: "list.test", Selector: "lists", PrivateKey: list,
		AuthResults: "list.test; arc=pass", Resolver: resolver, Time: 1784776060,
		ChainValidation: arrival,
	})
	if err != nil {
		t.Fatalf("list Seal: %v", err)
	}
	if second.ChainValidation != "pass" || !strings.Contains(second.AS, "cv=pass") {
		t.Fatalf("ARC-Seal should record the arrival status pass, got %q in %s", second.ChainValidation, second.AS)
	}
	if cv, reason := Verify(ctx, second.Message, resolver); cv != "pass" {
		t.Fatalf("the list's sealed message: %s (%s)", cv, reason)
	}

	// Changes after sealing are not covered.
	for name, after := range map[string][]byte{
		"subject": bytes.Replace(second.Message, []byte("[list]"), []byte("[other]"), 1),
		"body":    bytes.Replace(second.Message, []byte("list footer"), []byte("late footer"), 1),
	} {
		if cv, _ := Verify(ctx, after, resolver); cv != "fail" {
			t.Errorf("%s changed after sealing: want fail, got %s", name, cv)
		}
	}

	// Without the arrival status, Seal can only judge the bytes it is given:
	// the modified message, whose first-hop AMS no longer verifies.
	blind, err := Seal(ctx, modified, SealOptions{
		Domain: "list.test", Selector: "lists", PrivateKey: list, Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("Seal without ChainValidation: %v", err)
	}
	if blind.ChainValidation != "fail" {
		t.Errorf("computed cv over modified bytes: want fail, got %s", blind.ChainValidation)
	}
}

// TestSeal_ChainValidationMustMatchTheChain refuses an arrival status that
// cannot describe the message: none with a chain on it, pass or fail without
// one, or a value RFC 8617 §4.1.3 does not define.
//
// checklist: ARC-SEAL-04
func TestSeal_ChainValidationMustMatchTheChain(t *testing.T) {
	ctx := context.Background()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	opts := func(cv string) SealOptions {
		return SealOptions{Domain: "example.test", Selector: "arc", PrivateKey: priv, Resolver: resolver, ChainValidation: cv}
	}
	first, err := Seal(ctx, []byte(arcBaseMessage()), opts("none"))
	if err != nil {
		t.Fatalf("Seal with cv none on a fresh message: %v", err)
	}
	if first.ChainValidation != "none" {
		t.Fatalf("want none, got %s", first.ChainValidation)
	}
	for _, tc := range []struct {
		name string
		msg  []byte
		cv   string
	}{
		{"pass without a chain", []byte(arcBaseMessage()), "pass"},
		{"fail without a chain", []byte(arcBaseMessage()), "fail"},
		{"none on a chain", first.Message, "none"},
		{"undefined value", first.Message, "PASS"},
	} {
		if _, err := Seal(ctx, tc.msg, opts(tc.cv)); !errors.Is(err, ErrChainValidation) {
			t.Errorf("%s: want ErrChainValidation, got %v", tc.name, err)
		}
	}
	failed, err := Seal(ctx, first.Message, opts("fail"))
	if err != nil {
		t.Fatalf("Seal with cv fail on a chain: %v", err)
	}
	if !strings.Contains(failed.AS, "cv=fail") {
		t.Errorf("want cv=fail in %s", failed.AS)
	}
}

// TestSeal_RecordsCallerAuthResults checks that the AAR carries every result
// the caller passes, as given after the instance, and that the ARC-Seal covers
// it: the combined results of the ADMD's checks reach the next hop intact.
//
// checklist: ARC-HDR-02
func TestSeal_RecordsCallerAuthResults(t *testing.T) {
	ctx := context.Background()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	combined := "example.test; spf=pass smtp.mailfrom=alice@example.test; dkim=pass header.d=example.test; dmarc=pass header.from=example.test; arc=none"
	for _, tc := range []struct{ given, want string }{
		{combined, "ARC-Authentication-Results: i=1; " + combined},
		{"", "ARC-Authentication-Results: i=1; example.test; none"},
	} {
		res, err := Seal(ctx, []byte(arcBaseMessage()), SealOptions{
			Domain: "example.test", Selector: "arc", PrivateKey: priv, AuthResults: tc.given, Resolver: resolver,
		})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if res.AAR != tc.want {
			t.Errorf("AAR = %q, want %q", res.AAR, tc.want)
		}
		if !bytes.Contains(res.Message, []byte(tc.want+"\r\n")) {
			t.Errorf("sealed message does not carry %q", tc.want)
		}
		if tc.given == "" {
			continue
		}
		tampered := bytes.Replace(res.Message, []byte("dmarc=pass"), []byte("dmarc=fail"), 1)
		if cv, _ := Verify(ctx, tampered, resolver); cv != "fail" {
			t.Errorf("a changed AAR result should fail the seal, got %s", cv)
		}
	}
}
