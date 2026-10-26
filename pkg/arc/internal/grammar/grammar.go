package grammar

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rest-mail/go-dkim/pkg/dkim"
)

// IsARCField reports whether a lowercased header field name is one of the
// three ARC header fields (RFC 8617 §4.1).
func IsARCField(name string) bool {
	return name == "arc-authentication-results" || name == "arc-message-signature" || name == "arc-seal"
}

// Instance returns the instance of an ARC header field, given its
// lowercased name and its value, or an error naming the defect.
//
// The ARC-Message-Signature and ARC-Seal are DKIM tag-lists (RFC 8617 §4.1.2,
// §4.1.3, importing RFC 6376 §3.2), read strictly: a tag name outside the
// ABNF, a repeated tag, or an empty tag-spec (";;") makes the field malformed,
// rather than taking one reading of it that another verifier might not share.
// Tag names are case-sensitive, so the instance is the i= tag; I= is an
// unknown tag. Their ABNF puts the instance first, as instance [CFWS] ";"
// tag-list (§4.1.2, §4.1.3), and a leading instance may carry CFWS comments
// like the AAR's (§3.9): "(hop) i (x)= 1 (y);" is the instance 1, and the rest
// of the field is read as the strict tag-list, with no second i=. The i= tag
// may also appear anywhere else in the list, as it does in the fields many
// sealers write; there it is an ordinary tag-spec, with no comments.
//
// The ARC-Authentication-Results is not a tag-list: RFC 8617 §4.1.1 defines it
// as arc-info = instance [CFWS] ";" authres-payload, so the i= tag comes first,
// with comments allowed around its parts, and a ";" follows it. The payload's syntax does not affect the chain
// (§3.4), so it is not parsed; its methods legally repeat.
func Instance(name, value string) (int, error) {
	if name == "arc-authentication-results" {
		return aarInstance(value)
	}
	if digits, rest, err := leadingInstance(value); err == nil {
		tags, err := strictTagList(rest)
		if err != nil {
			return 0, err
		}
		if _, ok := tags["i"]; ok {
			return 0, fmt.Errorf("repeated i= instance tag")
		}
		return parseInstance(digits)
	}
	tags, err := strictTagList(value)
	if err != nil {
		return 0, err
	}
	raw, ok := tags["i"]
	if !ok {
		return 0, fmt.Errorf("missing required i= instance tag")
	}
	return parseInstance(raw)
}

// aarInstance reads the instance at the start of an ARC-Authentication-Results
// value by RFC 8617 §4.1.1 and §3.9:
//
//	arc-info = instance [CFWS] ";" authres-payload
//	instance = [CFWS] %s"i" [CFWS] "=" [CFWS] position
//
// CFWS is RFC 5322 §3.2.2 folding whitespace and comments, which may nest and
// hold quoted-pairs, so "i=1 (first hop);" and "(x) i (y)= 1;" are the
// instance 1.
func aarInstance(value string) (int, error) {
	digits, _, err := leadingInstance(value)
	if err != nil {
		return 0, err
	}
	return parseInstance(digits)
}

// leadingInstance reads the RFC 8617 §3.9 instance at the start of an ARC
// header field value, up to and including the [CFWS] ";" after it. It returns
// the instance digits, still to be checked by parseInstance, and the rest of
// the value after the ";".
func leadingInstance(value string) (digits, rest string, err error) {
	missing := fmt.Errorf("missing required i= instance tag at the start of the field")
	if rest, err = skipCFWS(value); err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(rest, "i") {
		return "", "", missing
	}
	if rest, err = skipCFWS(rest[1:]); err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(rest, "=") {
		return "", "", missing
	}
	if rest, err = skipCFWS(rest[1:]); err != nil {
		return "", "", err
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	digits = rest[:end]
	if rest, err = skipCFWS(rest[end:]); err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(rest, ";") {
		if rest != "" {
			return "", "", fmt.Errorf("malformed i= instance %q (want a 1..%d decimal with no sign or leading zero)", digits+rest, maxInstance)
		}
		return "", "", fmt.Errorf("no \";\" after the i= instance tag")
	}
	return digits, rest[1:], nil
}

// skipCFWS returns s without its leading CFWS (RFC 5322 §3.2.2): folding
// whitespace and comments, which nest and may hold quoted-pairs. A comment
// that is not closed is an error.
func skipCFWS(s string) (string, error) {
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		if !strings.HasPrefix(s, "(") {
			return s, nil
		}
		depth, i := 0, 0
		for ; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++ // quoted-pair: the next character is literal
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if depth != 0 {
			return "", fmt.Errorf("unclosed comment before the i= instance")
		}
		s = s[i+1:]
	}
}

// TrimFWS removes the folding whitespace RFC 5322 §3.2.2 allows around a tag,
// a value or an h= entry (SP, HTAB, CR and LF), and nothing else.
// strings.TrimSpace would also strip form feeds and Unicode spaces, which the
// ABNF doesn't allow there.
func TrimFWS(s string) string { return strings.Trim(s, " \t\r\n") }

// strictTagList parses a DKIM tag-list as dkim.ParseTagListStrict does (tag
// names and values by the RFC 6376 §3.2 ABNF, no repeated tag) and also
// refuses an empty tag-spec, which the ABNF allows only as the one optional
// ";" at the end.
func strictTagList(value string) (map[string]string, error) {
	tags, err := dkim.ParseTagListStrict(value)
	if err != nil {
		return nil, err
	}
	segs := strings.Split(value, ";")
	for _, seg := range segs[:len(segs)-1] {
		if TrimFWS(seg) == "" {
			return nil, fmt.Errorf("empty tag-spec in tag-list")
		}
	}
	return tags, nil
}

// maxInstance is the RFC 8617 §4.2.1 ceiling on an individual ARC set's
// instance number: i ranges over 1..50. It equals the §5.1.1 ceiling of 50
// ARC sets per chain — a contiguous chain's highest instance is its set count —
// but names the per-set range constraint parseInstance enforces, distinct from
// the chain-length ceiling arc.Verify checks.
const maxInstance = 50

// parseInstance validates the value of an i= instance tag. A conformant
// instance is a bare decimal in 1..50 (RFC 8617 §3.9 "position = 1*2DIGIT",
// §4.2.1 range): no sign, no leading zero, no surrounding cruft, no overflow.
// It returns the instance on success, or an error naming the defect.
func parseInstance(raw string) (int, error) {
	if !validInstanceDigits(raw) {
		return 0, fmt.Errorf("malformed i= instance %q (want a 1..%d decimal with no sign or leading zero)", raw, maxInstance)
	}
	n, _ := strconv.Atoi(raw) // one or two digits: cannot fail
	if n > maxInstance {
		return 0, fmt.Errorf("i= instance %q out of range 1..%d", raw, maxInstance)
	}
	return n, nil
}

// validInstanceDigits reports whether s is the canonical decimal form of an ARC
// instance: 1 or 2 ASCII digits with no leading zero (RFC 8617 §3.9
// "position = 1*2DIGIT", canonical). It rejects "" , "007"/"01" (zero-padded or
// >2 digits), "0", "-3", "+1", "1 ", "1a", and any overflow, so only 1..99 in
// canonical form pass here; parseInstance additionally enforces the 1..50 range.
func validInstanceDigits(s string) bool {
	if len(s) < 1 || len(s) > 2 {
		return false
	}
	if s[0] < '1' || s[0] > '9' { // first digit non-zero: no leading zero, no sign
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
