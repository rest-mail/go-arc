package arc

import (
	"context"
	"strings"

	"github.com/rest-mail/go-arc/pkg/arc/internal/grammar"
	"github.com/rest-mail/go-dkim/pkg/dkim"
)

// VerifyOptions configures VerifyChain. The zero value verifies with the
// system DNS resolver and does not compute oldest-pass.
type VerifyOptions struct {
	// Resolver fetches the DNS TXT keys of the ARC-Message-Signatures and
	// ARC-Seals. It matches net.Resolver.LookupTXT; nil uses the system
	// resolver.
	Resolver dkim.TXTResolver
	// OldestPass asks for the RFC 8617 §5.2 step 5 oldest-pass value on a
	// passing chain. Each ARC-Message-Signature older than the most recent one
	// costs one more key lookup and signature check, so it is off by default.
	OldestPass bool
}

// ChainResult is what VerifyChain found: the chain validation status, the ARC
// sets it read, and, when asked for, the oldest-pass value.
type ChainResult struct {
	// Status is the chain validation status, "pass", "fail" or "none", as
	// Verify returns it.
	Status string
	// Reason is the human-readable reason Verify returns with the status.
	Reason string
	// Sets holds one entry per ARC set, ordered by instance from 1 to N. It is
	// filled only for a chain that passed the structural checks (at most 50
	// sets, numbered 1 to N with no gap, each set complete with one field of
	// each kind), so it can be non-empty when Status is "fail" because a seal
	// or signature did not verify, and is empty for a chain too malformed to
	// read.
	//
	// The entries are what each hop recorded. A passing chain proves that
	// each sealer added its set and that no one changed it since; it does not
	// make any hop's assessment true. Trust an assessment only as far as you
	// trust the domain that sealed it (RFC 8617 §7.2.1, §9.4).
	Sets []ChainSet
	// OldestPass is the RFC 8617 §5.2 step 5 oldest-pass value: the lowest
	// instance whose ARC-Message-Signature still verifies, counting down from
	// the most recent, or 0 when every ARC-Message-Signature verifies. A host
	// records it as header.oldest-pass with the arc result in its
	// Authentication-Results field (RFC 8617 §6). It is meaningful only when
	// OldestPassChecked is true.
	OldestPass int
	// OldestPassChecked reports whether OldestPass was computed: true only
	// when VerifyOptions.OldestPass was set and Status is "pass".
	OldestPassChecked bool
}

// ChainSet describes one ARC set as its sealer recorded it.
type ChainSet struct {
	// Instance is the set's i= value, 1 for the first hop.
	Instance int
	// SealDomain and SealSelector are the ARC-Seal's d= and s=: the domain
	// that sealed this set and the selector of its key. RFC 8617 §7.2.2 names
	// them in a DMARC report.
	SealDomain   string
	SealSelector string
	// ChainValidation is the cv= the sealer recorded in its ARC-Seal: "none"
	// at instance 1 and "pass" at every later instance of a chain that
	// passes.
	ChainValidation string
	// SignatureDomain and SignatureSelector are the ARC-Message-Signature's d=
	// and s=.
	SignatureDomain   string
	SignatureSelector string
	// AuthResults is the ARC-Authentication-Results payload after "i=N;", as
	// written, for a host that parses Authentication-Results itself.
	AuthResults string
	// Assessment is AuthResults read as an RFC 8601 authres-payload. RFC 8617
	// §3.4 does not let the payload's syntax affect the chain, so a payload
	// that does not parse gives only the parts that do.
	Assessment Assessment
}

// Assessment is an ARC-Authentication-Results payload read as RFC 8601
// Authentication-Results: who made the assessment and the result of each
// method.
type Assessment struct {
	// AuthServID is the authserv-id, the ADMD that made the assessment.
	AuthServID string
	// Results holds each method's result in the order written. It is empty
	// for "none" (no-result).
	Results []MethodResult
}

// MethodResult is one resinfo of an Authentication-Results payload, such as
// "dkim=pass header.d=example.com".
type MethodResult struct {
	// Method is the authentication method, lowercased, such as "spf",
	// "dkim", "dmarc" or "arc". A method version ("dkim/1") is dropped.
	Method string
	// Result is the method's result, lowercased, such as "pass" or "fail".
	Result string
	// Reason is the reason= value, if any.
	Reason string
	// Properties holds the propspecs in the order written.
	Properties []Property
}

// Property is one propspec of a resinfo, such as header.d=example.com.
type Property struct {
	// Type is the ptype, lowercased: "smtp", "header", "body" or "policy".
	Type string
	// Name is the property, lowercased, such as "d" or "mailfrom".
	Name string
	// Value is the pvalue as written, unquoted.
	Value string
}

// VerifyChain validates the ARC chain in a raw message exactly as Verify does
// and returns the status and reason with what the chain records: one ChainSet
// per ARC set, and the oldest-pass value when opts.OldestPass is set and the
// chain passes.
func VerifyChain(ctx context.Context, rawMessage []byte, opts VerifyOptions) ChainResult {
	var res ChainResult
	res.Status, res.Reason = verifyChain(ctx, rawMessage, opts, &res)
	return res
}

// chainSets describes the complete, contiguous sets 1..n.
func chainSets(sets map[int]*arcSet, n int) []ChainSet {
	out := make([]ChainSet, 0, n)
	for i := 1; i <= n; i++ {
		s := sets[i]
		as := dkim.ParseTagList(s.as.Value)
		ams := dkim.ParseTagList(s.ams.Value)
		payload, _ := grammar.AARPayload(s.aar.Value) // collectARCSets already read the instance
		out = append(out, ChainSet{
			Instance:          i,
			SealDomain:        grammar.TrimFWS(as["d"]),
			SealSelector:      grammar.TrimFWS(as["s"]),
			ChainValidation:   grammar.TrimFWS(as["cv"]),
			SignatureDomain:   grammar.TrimFWS(ams["d"]),
			SignatureSelector: grammar.TrimFWS(ams["s"]),
			AuthResults:       grammar.TrimFWS(payload),
			Assessment:        parseAssessment(payload),
		})
	}
	return out
}

// parseAssessment reads an authres-payload (RFC 8601 §2.2):
//
//	authres-payload = [CFWS] authserv-id [ CFWS authres-version ]
//	                  ( no-result / 1*resinfo ) [CFWS]
//	resinfo         = [CFWS] ";" methodspec [ CFWS reasonspec ]
//	                  [ CFWS 1*propspec ]
//
// It is lenient: comments are dropped, and a resinfo that does not start
// with method=result is skipped.
func parseAssessment(payload string) Assessment {
	parts := splitOutsideQuotes(stripComments(payload), ';')
	var a Assessment
	a.AuthServID, _, _ = nextWord(parts[0])
	for _, part := range parts[1:] {
		if r, ok := parseResinfo(part); ok {
			a.Results = append(a.Results, r)
		}
	}
	return a
}

// parseResinfo reads one methodspec [reasonspec] [propspec...], with the
// comments already removed. "none" (no-result) is not a resinfo.
func parseResinfo(s string) (MethodResult, bool) {
	method, rest, ok := nextPair(s)
	if !ok {
		return MethodResult{}, false
	}
	if slash := strings.IndexByte(method[0], '/'); slash >= 0 {
		method[0] = method[0][:slash]
	}
	r := MethodResult{
		Method: strings.ToLower(grammar.TrimFWS(method[0])),
		Result: strings.ToLower(method[1]),
	}
	if r.Method == "" || r.Result == "" {
		return MethodResult{}, false
	}
	for {
		var kv [2]string
		if kv, rest, ok = nextPair(rest); !ok {
			break
		}
		name := strings.ToLower(kv[0])
		if name == "reason" {
			r.Reason = kv[1]
			continue
		}
		if dot := strings.IndexByte(name, '.'); dot > 0 {
			r.Properties = append(r.Properties, Property{Type: name[:dot], Name: name[dot+1:], Value: kv[1]})
		}
	}
	return r, true
}

// nextPair reads "name [FWS] = [FWS] value" from the start of s and returns
// the name, the value (unquoted if quoted) and the rest of s.
func nextPair(s string) ([2]string, string, bool) {
	name, rest, quoted := nextWord(s)
	if name == "" || quoted {
		return [2]string{}, s, false
	}
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !strings.HasPrefix(rest, "=") {
		return [2]string{}, s, false
	}
	value, rest, _ := nextWord(rest[1:])
	return [2]string{name, value}, rest, true
}

// nextWord returns the first word of s, after leading whitespace: a quoted
// string (unquoted, reporting quoted) or a run of characters up to
// whitespace or "=".
func nextWord(s string) (word, rest string, quoted bool) {
	s = strings.TrimLeft(s, " \t\r\n")
	if strings.HasPrefix(s, `"`) {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				if i+1 < len(s) {
					i++
					b.WriteByte(s[i])
				}
			case '"':
				return b.String(), s[i+1:], true
			default:
				b.WriteByte(s[i])
			}
		}
		return b.String(), "", true
	}
	end := strings.IndexAny(s, " \t\r\n=")
	if end < 0 {
		return s, "", false
	}
	return s[:end], s[end:], false
}

// stripComments replaces each RFC 5322 comment outside a quoted string with
// a space. Comments nest and hold quoted-pairs; an unclosed one runs to the
// end.
func stripComments(s string) string {
	var b strings.Builder
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case depth > 0:
			switch c {
			case '\\':
				i++
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					b.WriteByte(' ')
				}
			}
		case inQuote:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
			b.WriteByte(c)
		case c == '(':
			depth = 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// splitOutsideQuotes splits s at each sep that is not inside a quoted string.
func splitOutsideQuotes(s string, sep byte) []string {
	var parts []string
	start, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case inQuote && s[i] == '\\':
			i++
		case s[i] == '"':
			inQuote = !inQuote
		case !inQuote && s[i] == sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}
