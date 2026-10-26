package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim"
)

// TestRFC_MalformedFieldsFail breaks one field of a valid single-set chain at
// a time and checks that the chain fails for that reason, not another one.
//
// checklist: ARC-HDR-01 ARC-HDR-15 ARC-HDR-17 ARC-VAL-15 ARC-VAL-16
func TestRFC_MalformedFieldsFail(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)
	if cv, reason := Verify(context.Background(), []byte(raw), resolver); cv != "pass" {
		t.Fatalf("precondition: want pass, got %s (%s)", cv, reason)
	}

	for _, tc := range []struct {
		name, old, new, reason string
	}{
		{"AAR instance not first", "ARC-Authentication-Results: i=1; example.test", "ARC-Authentication-Results: example.test; i=1", "at the start"},
		{"AAR without payload", "ARC-Authentication-Results: i=1; example.test; spf=pass", "ARC-Authentication-Results: i=1", `no ";"`},
		{"AS empty tag-spec", "ARC-Seal: i=1; a=rsa-sha256;", "ARC-Seal: i=1;; a=rsa-sha256;", "empty tag-spec"},
		{"AS upper-case instance tag", "ARC-Seal: i=1;", "ARC-Seal: I=1;", "missing required i="},
		{"AS bad tag name", "ARC-Seal: i=1;", "ARC-Seal: i=1; 1x=y;", "ARC-Seal"},
		{"AS rsa-sha1", "ARC-Seal: i=1; a=rsa-sha256;", "ARC-Seal: i=1; a=rsa-sha1;", "rsa-sha1 is historic"},
		{"AS algorithm in upper case", "ARC-Seal: i=1; a=rsa-sha256;", "ARC-Seal: i=1; a=RSA-SHA256;", "unsupported ARC-Seal algorithm RSA-SHA256"},
		{"AS ed25519", "ARC-Seal: i=1; a=rsa-sha256;", "ARC-Seal: i=1; a=ed25519-sha256;", "unsupported ARC-Seal algorithm ed25519-sha256"},
		{"AS d= not a DNS name", "d=example.test; s=arc; t=", "d=example..test; s=arc; t=", "not a DNS name"},
		{"AS s= not a DNS name", "s=arc; t=", "s=a/rc; t=", "not a DNS name"},
		{"AMS rsa-sha1", "a=rsa-sha256; c=relaxed", "a=rsa-sha1; c=relaxed", "ARC-Message-Signature (i=1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(raw, tc.old) {
				t.Fatalf("message does not contain %q", tc.old)
			}
			msg := strings.Replace(raw, tc.old, tc.new, 1)
			cv, reason := Verify(context.Background(), []byte(msg), resolver)
			if cv != "fail" || !strings.Contains(reason, tc.reason) {
				t.Errorf("got %s (%s), want fail for %q", cv, reason, tc.reason)
			}
		})
	}
}

// sealChainBadSeal builds a three-set chain like sealChain, except that the
// ARC-Seal at instance bad is signed with another key than the one published.
// Every later seal signs that seal as it is, so only it fails to verify.
func sealChainBadSeal(t *testing.T, good, other *rsa.PrivateKey, bad int) string {
	t.Helper()
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))
	var prepend strings.Builder
	chain := []*arcSet{}
	for i := 1; i <= 3; i++ {
		aar := mkHeader("ARC-Authentication-Results", fmt.Sprintf("i=%d; example.test; spf=pass", i))
		ams := mkHeader("ARC-Message-Signature", signAMS(t, good, "example.test", "arc", i, msgHeaders, body))
		set := &arcSet{aar: aar, ams: ams}
		chain = append(chain, set)
		cv, key := "pass", good
		if i == 1 {
			cv = "none"
		}
		if i == bad {
			key = other
		}
		set.as = mkHeader("ARC-Seal", signAS(t, key, "example.test", "arc", i, cv, chain))
		prepend.WriteString(set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n")
	}
	return prepend.String() + base
}

// TestRFC_BrokenChainAtEachPosition breaks the chain at each of its three
// seals in turn: the chain fails, and the reason names that seal.
//
// checklist: ARC-VAL-09
func TestRFC_BrokenChainAtEachPosition(t *testing.T) {
	good, _ := rsa.GenerateKey(rand.Reader, 1024)
	other, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, good), "arc", "example.test")
	for bad := 1; bad <= 3; bad++ {
		raw := sealChainBadSeal(t, good, other, bad)
		cv, reason := Verify(context.Background(), []byte(raw), resolver)
		if want := fmt.Sprintf("ARC-Seal (i=%d)", bad); cv != "fail" || !strings.Contains(reason, want) {
			t.Errorf("seal %d broken: got %s (%s), want fail at %s", bad, cv, reason, want)
		}
	}
}

// TestRFC_DNSFailureIsFail checks that a temporary DNS error is permanent for
// ARC: the chain fails rather than being retried or reported as none.
//
// checklist: ARC-VAL-13
func TestRFC_DNSFailureIsFail(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := sealChain(t, priv, "example.test", "arc", 1)
	resolver := func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if cv, reason := Verify(context.Background(), []byte(raw), resolver); cv != "fail" {
		t.Errorf("got %s (%s), want fail", cv, reason)
	}
}

// TestSeal_StopsOnFailedChain checks that Seal adds nothing to a message whose
// most recent ARC-Seal already says cv=fail.
//
// checklist: ARC-SEAL-02
func TestSeal_StopsOnFailedChain(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChainCV(t, priv, "example.test", "arc", []string{"none", "fail"})
	_, err := Seal(context.Background(), []byte(raw), SealOptions{
		Domain: "example.test", Selector: "arc", PrivateKey: priv, Resolver: resolver, Time: 1784776000,
	})
	if !errors.Is(err, ErrChainFailed) {
		t.Fatalf("got %v, want ErrChainFailed", err)
	}
}

// TestSeal_RefusesPastMaxInstance checks that Seal adds no 51st ARC Set.
//
// checklist: ARC-SEAL-07
func TestSeal_RefusesPastMaxInstance(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := sealChain(t, priv, "example.test", "arc", maxARCSets)
	_, err := Seal(context.Background(), []byte(raw), SealOptions{
		Domain: "example.test", Selector: "arc", PrivateKey: priv, Time: 1784776000,
	})
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("got %v, want an error about the maximum", err)
	}
}

// TestSeal_RejectsInvalidDomainOrSelector checks that Seal writes only DNS
// names into d= and s=, and only a canonicalization it knows into c=.
//
// checklist: ARC-SEAL-08
func TestSeal_RejectsInvalidDomainOrSelector(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	for _, opt := range []SealOptions{
		{Domain: "example..test", Selector: "arc"},
		{Domain: "bücher.example", Selector: "arc"},
		{Domain: "example.test; x=y", Selector: "arc"},
		{Domain: "example.test", Selector: "a;b"},
		{Domain: strings.Repeat("a", 64) + ".test", Selector: "arc"},
		{Domain: strings.Repeat("a.", 127) + "test", Selector: "arc"},
		{Domain: "example.test", Selector: "arc", HeaderCanon: "nofws"},
		{Domain: "example.test", Selector: "arc", BodyCanon: "nofws"},
	} {
		opt.PrivateKey = priv
		if _, err := Seal(context.Background(), []byte(arcBaseMessage()), opt); err == nil {
			t.Errorf("d=%q s=%q: want an error", opt.Domain, opt.Selector)
		}
	}
}

// TestSeal_SignsDKIMSignatures checks that by default the AMS signs every
// DKIM-Signature on the message, and that the chain still verifies.
//
// checklist: ARC-HDR-10
func TestSeal_SignsDKIMSignatures(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	msg := "DKIM-Signature: v=1; a=rsa-sha256; d=a.test; s=x; h=from; bh=AA==; b=AA==\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=b.test; s=y; h=from; bh=AA==; b=AA==\r\n" +
		arcBaseMessage()
	opt := SealOptions{Domain: "example.test", Selector: "arc", PrivateKey: priv, Resolver: resolver, Time: 1784776000}
	res, err := Seal(context.Background(), []byte(msg), opt)
	if err != nil {
		t.Fatal(err)
	}
	if h := amsHTag(t, res.AMS); !strings.HasSuffix(h, ":dkim-signature:dkim-signature") {
		t.Errorf("h=%q, want both DKIM-Signature fields signed", h)
	}
	if cv, reason := Verify(context.Background(), res.Message, resolver); cv != "pass" {
		t.Errorf("got %s (%s), want pass", cv, reason)
	}

	opt.Headers = []string{"from", "subject"}
	res, err = Seal(context.Background(), []byte(msg), opt)
	if err != nil {
		t.Fatal(err)
	}
	if h := amsHTag(t, res.AMS); h != "from:subject" {
		t.Errorf("h=%q with explicit headers, want from:subject", h)
	}
}
