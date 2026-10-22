package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim"
)

// FuzzFieldInstance reads any ARC header field value: it never panics, and an
// instance it accepts is 1 to 50 and comes from an i= tag in the value, which
// may have CFWS around a leading instance's parts (RFC 8617 §3.9) or folding
// whitespace before a non-leading tag's "=" (RFC 6376 §3.2).
//
// checklist: ARC-HDR-15 ARC-SET-01
func FuzzFieldInstance(f *testing.F) {
	for _, seed := range []string{
		"i=1; example.test; spf=pass", "example.test; i=1", "i=50; a=rsa-sha256; d=x; s=y; cv=pass; b=",
		"i=01; a=b", "i=1a; a=b", "i=1;; a=b", "I=1; a=b", "a=b; i=2", "i=51", "i=1; i=2", "i=-1", "i=", ";", "",
		"i =1; a=b", "i\r\n =1; a=b", " i = 1 ; example.test",
		"i=1 (hop); example.test", "(c) i (c)=(c (n)) 1 (c);", `i=1 (\)) ;`, "i=1 (open;",
		"i (nested (comment)) = 1; a=b", `i (escaped \)) = 1; a=b`, "i (folded\r\n comment) = 1; a=b",
	} {
		for _, name := range []string{"arc-authentication-results", "arc-message-signature", "arc-seal"} {
			f.Add(name, seed)
		}
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		if !isARCField(name) {
			return
		}
		n, err := fieldInstance(name, value)
		if err != nil {
			return
		}
		if n < 1 || n > maxInstance {
			t.Fatalf("instance %d out of range", n)
		}
		// Every ARC field permits comments before a leading i and its =.
		// Check those tokens without assuming the value matches iTag.
		rest, _ := skipCFWS(value)
		if strings.HasPrefix(rest, "i") {
			if rest, _ = skipCFWS(rest[1:]); strings.HasPrefix(rest, "=") {
				return
			}
		}
		// Only AMS/AS permit a non-leading instance, as a strict tag-spec.
		if name == "arc-authentication-results" || !iTag.MatchString(value) {
			t.Fatalf("instance %d from a value with no i= tag", n)
		}
	})
}

// iTag matches an i= tag name with the folding whitespace a tag-spec allows
// before its "=".
var iTag = regexp.MustCompile("i[ \t\r\n]*=")

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
