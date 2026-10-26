package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim/pkg/dkim"
)

// FuzzVerify validates any message, seeded with valid chains of one and two
// sets and broken ones: it never panics, the status is none, pass or fail,
// and a message without an ARC header field is none. No DNS is queried.
//
// checklist: ARC-VAL-01
func FuzzVerify(f *testing.F) {
	fuzzKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		sealChain(f, fuzzKey, "example.test", "arc", 1),
		sealChain(f, fuzzKey, "example.test", "arc", 2),
		sealChainCV(f, fuzzKey, "example.test", "arc", []string{"none", "fail"}),
		gappedChain(f, fuzzKey, "example.test", "arc", 1, 3),
		arcBaseMessage(),
		"ARC-Seal: i=1\r\n\r\n",
		"ARC-Authentication-Results: i=1; x\r\nARC-Message-Signature: i=1; h=from; b=; bh=\r\nARC-Seal: i=1; cv=none; b=\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}
	txt, err := dkim.RecordValue(publicPEM(f, fuzzKey))
	if err != nil {
		f.Fatal(err)
	}
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name == "arc._domainkey.example.test" {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		cv, reason := Verify(context.Background(), msg, resolver)
		switch cv {
		case "none", "pass", "fail":
		default:
			t.Fatalf("status %q (%s)", cv, reason)
		}
		if cv != "none" && !hasARCField(msg) {
			t.Fatalf("status %s (%s) for a message with no ARC header field", cv, reason)
		}
	})
}

// hasARCField reports whether a message's header block names an ARC header
// field anywhere, as a field name or not.
func hasARCField(msg []byte) bool {
	lower := strings.ToLower(string(msg))
	return strings.Contains(lower, "arc-seal") || strings.Contains(lower, "arc-message-signature") ||
		strings.Contains(lower, "arc-authentication-results")
}
