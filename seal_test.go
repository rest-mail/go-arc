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

// TestSeal_DuplicateIncomingChainRejected confirms Seal refuses to extend an
// incoming chain that carries a duplicate ARC field at some instance (RFC 8617
// §5.1.1): the set is malformed and cannot be deterministically sealed over, so
// Seal returns an error rather than picking one copy.
func TestSeal_DuplicateIncomingChainRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	for _, name := range []string{"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
		t.Run(name, func(t *testing.T) {
			raw := sealChain(t, priv, "example.test", "arc", 1)
			dup := duplicateFirstHeader(t, raw, name)

			_, err := Seal(context.Background(), []byte(dup), SealOptions{
				Domain:      "example.test",
				Selector:    "arc",
				PrivateKey:  priv,
				AuthResults: "example.test; arc=fail",
				Resolver:    resolver,
			})
			if err == nil {
				t.Fatalf("want error sealing over duplicate %s, got nil", name)
			}
			if !strings.Contains(err.Error(), "malformed") {
				t.Errorf("expected a malformed-chain error, got: %v", err)
			}
		})
	}
}

// TestSeal_IncompleteIncomingChainRejected confirms Seal refuses to extend an
// incoming chain carrying a structurally incomplete prior ARC set — an instance
// missing one of its three fields (here an ARC-Authentication-Results with no
// matching ARC-Message-Signature or ARC-Seal). Such a set is malformed (RFC 8617
// §5.2 step 3A); before the fix Seal dereferenced the nil field in arcSealBase
// and panicked (issue #8). It must return an explicit malformed-chain error
// instead, mirroring the completeness rule Verify already applies, so a forwarder
// that does not control its inbound chain never crashes on a crafted set.
func TestSeal_IncompleteIncomingChainRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	// A message carrying only an ARC-Authentication-Results for i=1: the set is
	// present but has no ARC-Message-Signature and no ARC-Seal.
	incomplete := "ARC-Authentication-Results: i=1; example.test; spf=pass\r\n" + arcBaseMessage()

	// Recover so the pre-fix nil-pointer panic surfaces as a clear test failure
	// (proving the bug) rather than crashing the whole test binary.
	var (
		res     *SealResult
		sealErr error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Seal panicked on an incomplete incoming ARC set (issue #8): %v", r)
			}
		}()
		res, sealErr = Seal(context.Background(), []byte(incomplete), SealOptions{
			Domain:      "example.test",
			Selector:    "arc",
			PrivateKey:  priv,
			AuthResults: "example.test; arc=fail",
			Resolver:    resolver,
		})
	}()

	if sealErr == nil {
		t.Fatalf("want error sealing over an incomplete incoming ARC set, got nil (res=%+v)", res)
	}
	if !strings.Contains(sealErr.Error(), "malformed") {
		t.Errorf("expected a malformed-chain error, got: %v", sealErr)
	}
}

// TestSeal_CVFailSealScope covers RFC 8617 §5.1.2: the scope of the ARC-Seal
// signature depends on the chain-validation status this MTA computes.
//
//   - cv=fail: the chain being extended is broken, so the new ARC-Seal MUST be
//     computed over ONLY the ARC set this MTA just created — the prior (failed)
//     sets MUST NOT be signed. Signing the whole prior chain is what lets a
//     broken chain be re-sealed as if intact (the "healing" bug of issue #13).
//   - cv=pass / cv=none: the new ARC-Seal covers every prior ARC set plus the
//     new one, in instance order (unchanged behavior).
//
// The check is byte-exact: it re-runs the verifier's own arcSealBase over two
// candidate scopes — the new set alone vs the full chain — and asserts which one
// the produced signature verifies against. Before the fix, a cv=fail seal signed
// the full prior chain, so the "full chain" scope verified and the "current set
// only" scope did not — the reverse of what §5.1.2 requires.
func TestSeal_CVFailSealScope(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")

	// orderedSets returns the ARC sets of msg in ascending instance order.
	orderedSets := func(t *testing.T, msg []byte) []*arcSet {
		t.Helper()
		headers, _ := dkim.SplitMessage(msg)
		sets, err := collectARCSets(headers)
		if err != nil {
			t.Fatalf("collectARCSets: %v", err)
		}
		ordered := make([]*arcSet, 0, len(sets))
		for i := 1; i <= len(sets); i++ {
			s := sets[i]
			if s == nil || s.aar == nil || s.ams == nil || s.as == nil {
				t.Fatalf("i=%d incomplete set in sealed message", i)
			}
			ordered = append(ordered, s)
		}
		return ordered
	}

	t.Run("cv_fail_covers_only_current_set", func(t *testing.T) {
		// A valid single-set chain, then tamper its signed AAR so the chain the
		// next hop receives no longer verifies: the new seal must record cv=fail.
		first := sealChain(t, priv, "example.test", "arc", 1)
		broken := strings.Replace(first, "spf=pass", "spf=fail", 1)
		if broken == first {
			t.Fatal("test setup: failed to tamper the incoming chain")
		}

		res, err := Seal(context.Background(), []byte(broken), SealOptions{
			Domain:      "example.test",
			Selector:    "arc",
			PrivateKey:  priv,
			AuthResults: "example.test; arc=fail",
			Resolver:    resolver,
			Time:        1784776200,
		})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if res.ChainValidation != "fail" {
			t.Fatalf("precondition: want cv=fail over broken chain, got %s", res.ChainValidation)
		}

		ordered := orderedSets(t, res.Message)
		if len(ordered) != 2 {
			t.Fatalf("want a 2-set sealed message, got %d sets", len(ordered))
		}
		newOnly := ordered[len(ordered)-1:] // just the set this MTA added

		// RFC 8617 §5.1.2: the cv=fail ARC-Seal MUST verify over ONLY the new set.
		if r, reason := verifyARCSeal(context.Background(), newOnly, resolver); r != dkim.ResultPass {
			t.Errorf("cv=fail ARC-Seal must cover only the current instance's set, but it does not verify over that set alone: %s (%s)", r, reason)
		}
		// ...and it MUST NOT cover the prior (failed) chain.
		if r, _ := verifyARCSeal(context.Background(), ordered, resolver); r == dkim.ResultPass {
			t.Errorf("cv=fail ARC-Seal must NOT sign the prior chain, but it verifies over the full chain (RFC 8617 §5.1.2 scope violation, issue #13)")
		}
	})

	t.Run("cv_pass_covers_full_chain", func(t *testing.T) {
		// An intact single-set chain: the second hop records cv=pass and its seal
		// must cover the whole chain — the behavior this fix must leave unchanged.
		first := sealChain(t, priv, "example.test", "arc", 1)

		res, err := Seal(context.Background(), []byte(first), SealOptions{
			Domain:      "example.test",
			Selector:    "arc",
			PrivateKey:  priv,
			AuthResults: "example.test; arc=pass",
			Resolver:    resolver,
			Time:        1784776300,
		})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if res.ChainValidation != "pass" {
			t.Fatalf("precondition: want cv=pass over intact chain, got %s", res.ChainValidation)
		}

		ordered := orderedSets(t, res.Message)
		if len(ordered) != 2 {
			t.Fatalf("want a 2-set sealed message, got %d sets", len(ordered))
		}
		newOnly := ordered[len(ordered)-1:]

		// The cv=pass ARC-Seal MUST verify over the full chain...
		if r, reason := verifyARCSeal(context.Background(), ordered, resolver); r != dkim.ResultPass {
			t.Errorf("cv=pass ARC-Seal must cover the full chain, but it does not verify over it: %s (%s)", r, reason)
		}
		// ...and NOT over the new set alone.
		if r, _ := verifyARCSeal(context.Background(), newOnly, resolver); r == dkim.ResultPass {
			t.Errorf("cv=pass ARC-Seal must cover the prior chain, but it verifies over the new set alone (full-chain coverage regressed)")
		}
	})
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
