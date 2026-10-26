package grammar

import (
	"regexp"
	"strings"
	"testing"
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
		"(open i=1; a=b", "i (open =1; a=b", "i= (open 1; a=b",
	} {
		for _, name := range []string{"arc-authentication-results", "arc-message-signature", "arc-seal"} {
			f.Add(name, seed)
		}
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		if !IsARCField(name) {
			return
		}
		n, err := Instance(name, value)
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
