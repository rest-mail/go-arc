package arc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim"
)

// keyEntry is one signer served by keyResolver.
type keyEntry struct {
	priv     *rsa.PrivateKey
	selector string
	domain   string
}

// keyResolver serves each entry's public key at <selector>._domainkey.<domain>
// and NXDOMAINs everything else — a hermetic stand-in for DNS across multiple
// ARC signers.
func keyResolver(t *testing.T, entries ...keyEntry) dkim.TXTResolver {
	t.Helper()
	records := map[string]string{}
	for _, e := range entries {
		txt, err := dkim.RecordValue(publicPEM(t, e.priv))
		if err != nil {
			t.Fatalf("RecordValue: %v", err)
		}
		records[dkim.RecordName(e.selector, e.domain)] = txt
	}
	return func(_ context.Context, name string) ([]string, error) {
		if txt, ok := records[name]; ok {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

// TestSeal_SingleSetRoundTrip seals an unsealed message and verifies the result
// with go-arc's own verifier: pass, one set, cv=none for the first hop.
func TestSeal_SingleSetRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	res, err := Seal(context.Background(), []byte(arcBaseMessage()), SealOptions{
		Domain:      "example.test",
		Selector:    "arc",
		PrivateKey:  priv,
		AuthResults: "example.test; spf=pass smtp.mailfrom=alice@example.test; dkim=pass header.d=example.test",
		Resolver:    resolver,
		Time:        1784776000,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if res.Instance != 1 {
		t.Errorf("want instance 1, got %d", res.Instance)
	}
	if res.ChainValidation != "none" {
		t.Errorf("want cv=none for first hop, got %s", res.ChainValidation)
	}
	for _, f := range []struct{ name, got string }{
		{"ARC-Authentication-Results:", res.AAR},
		{"ARC-Message-Signature:", res.AMS},
		{"ARC-Seal:", res.AS},
	} {
		if !strings.HasPrefix(f.got, f.name) {
			t.Errorf("field does not start with %q: %q", f.name, f.got)
		}
	}

	cv, reason := Verify(context.Background(), res.Message, resolver)
	if cv != "pass" {
		t.Fatalf("Verify: want pass, got %s (%s)", cv, reason)
	}
	if !strings.Contains(reason, "1 set") {
		t.Errorf("want 1-set chain, reason: %s", reason)
	}
}

// TestSeal_TwoHopChain seals with two independent signers, one hop over the
// other's output, and verifies a 2-set chain: instance 2, cv=pass, intact.
func TestSeal_TwoHopChain(t *testing.T) {
	hop1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hop2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := keyResolver(t,
		keyEntry{hop1, "hop1", "a.example.test"},
		keyEntry{hop2, "hop2", "b.example.test"})

	first, err := Seal(context.Background(), []byte(arcBaseMessage()), SealOptions{
		Domain:      "a.example.test",
		Selector:    "hop1",
		PrivateKey:  hop1,
		AuthResults: "a.example.test; spf=pass smtp.mailfrom=alice@example.test",
		Resolver:    resolver,
		Time:        1784776000,
	})
	if err != nil {
		t.Fatalf("hop1 Seal: %v", err)
	}
	if first.ChainValidation != "none" {
		t.Fatalf("hop1 cv=%s, want none", first.ChainValidation)
	}

	second, err := Seal(context.Background(), first.Message, SealOptions{
		Domain:      "b.example.test",
		Selector:    "hop2",
		PrivateKey:  hop2,
		AuthResults: "b.example.test; arc=pass; dkim=pass header.d=a.example.test",
		Resolver:    resolver,
		Time:        1784776100,
	})
	if err != nil {
		t.Fatalf("hop2 Seal: %v", err)
	}
	if second.Instance != 2 {
		t.Errorf("want instance 2, got %d", second.Instance)
	}
	if second.ChainValidation != "pass" {
		t.Errorf("hop2 cv=%s, want pass (hop1 chain is intact)", second.ChainValidation)
	}

	cv, reason := Verify(context.Background(), second.Message, resolver)
	if cv != "pass" {
		t.Fatalf("Verify 2-set chain: want pass, got %s (%s)", cv, reason)
	}
	if !strings.Contains(reason, "2 set") {
		t.Errorf("want 2-set chain, reason: %s", reason)
	}
}

// TestSeal_TamperedBodyFails confirms that mutating the body after sealing
// breaks the ARC-Message-Signature and Verify fails.
func TestSeal_TamperedBodyFails(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	res, err := Seal(context.Background(), []byte(arcBaseMessage()), SealOptions{
		Domain:      "example.test",
		Selector:    "arc",
		PrivateKey:  priv,
		AuthResults: "example.test; spf=pass",
		Resolver:    resolver,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := bytes.Replace(res.Message, []byte("ARC body."), []byte("TAMPERED."), 1)
	cv, reason := Verify(context.Background(), tampered, resolver)
	if cv != "fail" {
		t.Fatalf("want fail on body tamper, got %s (%s)", cv, reason)
	}
	if !strings.Contains(reason, "ARC-Message-Signature") {
		t.Errorf("expected AMS failure, got: %s", reason)
	}
}

// TestSeal_BrokenIncomingChainRecordsFail confirms cv= reflects the received
// chain: sealing over a chain whose signed AAR was tampered records cv=fail.
func TestSeal_BrokenIncomingChainRecordsFail(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	first, err := Seal(context.Background(), []byte(arcBaseMessage()), SealOptions{
		Domain:      "example.test",
		Selector:    "arc",
		PrivateKey:  priv,
		AuthResults: "example.test; spf=pass",
		Resolver:    resolver,
	})
	if err != nil {
		t.Fatalf("first Seal: %v", err)
	}

	// Tamper the signed ARC-Authentication-Results: the seal over set 1 no longer
	// verifies, so the chain the next hop receives is broken.
	broken := bytes.Replace(first.Message, []byte("spf=pass"), []byte("spf=fail"), 1)

	second, err := Seal(context.Background(), broken, SealOptions{
		Domain:      "example.test",
		Selector:    "arc",
		PrivateKey:  priv,
		AuthResults: "example.test; arc=fail",
		Resolver:    resolver,
	})
	if err != nil {
		t.Fatalf("second Seal: %v", err)
	}
	if second.ChainValidation != "fail" {
		t.Errorf("want cv=fail over broken incoming chain, got %s", second.ChainValidation)
	}
}

// TestSeal_RequiredOptions rejects missing signing identity.
func TestSeal_RequiredOptions(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []SealOptions{
		{Selector: "arc", PrivateKey: priv},
		{Domain: "example.test", PrivateKey: priv},
		{Domain: "example.test", Selector: "arc"},
	}
	for i, opt := range cases {
		if _, err := Seal(context.Background(), []byte(arcBaseMessage()), opt); err == nil {
			t.Errorf("case %d: want error for incomplete options, got nil", i)
		}
	}
}
