package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim/pkg/dkim"
)

// testHop is one hop of a chain built by buildHops: who seals it, what it
// records, and the body its ARC-Message-Signature signs.
type testHop struct {
	sealDomain, sealSelector string
	amsDomain, amsSelector   string
	aar                      string // payload after "i=N; "
	body                     string
}

// buildHops seals one ARC set per hop with priv over arcBaseMessage's header
// fields and each hop's own body, and returns the message carrying all the
// sets with the last hop's body. A hop whose body differs from the final one
// leaves an ARC-Message-Signature that no longer verifies, as a mailing list
// footer does to the hop before it.
func buildHops(t *testing.T, priv *rsa.PrivateKey, hops []testHop) string {
	t.Helper()
	headers, _ := dkim.SplitMessage([]byte(arcBaseMessage()))
	var prepend strings.Builder
	var chain []*arcSet
	for idx, h := range hops {
		i := idx + 1
		set := &arcSet{
			aar: mkHeader("ARC-Authentication-Results", "i="+strconv.Itoa(i)+"; "+h.aar),
			ams: mkHeader("ARC-Message-Signature", signAMS(t, priv, h.amsDomain, h.amsSelector, i, headers, h.body)),
		}
		chain = append(chain, set)
		cv := "pass"
		if i == 1 {
			cv = "none"
		}
		set.as = mkHeader("ARC-Seal", signAS(t, priv, h.sealDomain, h.sealSelector, i, cv, chain))
		prepend.WriteString(set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n")
	}
	final := strings.Replace(arcBaseMessage(), "ARC body.\r\n", hops[len(hops)-1].body, 1)
	return prepend.String() + final
}

// threeHops returns three hops sealed by different domains, all signing body.
func threeHops(body string) []testHop {
	return []testHop{
		{"origin.test", "s1", "origin.test", "ams1", "origin.test; spf=pass smtp.mailfrom=alice@example.test; dkim=pass header.d=example.test", body},
		{"list.test", "s2", "list-ams.test", "ams2", "list.test 1; dmarc=pass (aligned) header.from=example.test; arc=none", body},
		{"forward.test", "s3", "forward.test", "ams3", "forward.test; none", body},
	}
}

// hopsResolver serves priv's key at every selector the hops name.
func hopsResolver(t *testing.T, priv *rsa.PrivateKey, hops []testHop) dkim.TXTResolver {
	t.Helper()
	var entries []keyEntry
	for _, h := range hops {
		entries = append(entries,
			keyEntry{priv: priv, selector: h.sealSelector, domain: h.sealDomain},
			keyEntry{priv: priv, selector: h.amsSelector, domain: h.amsDomain})
	}
	return keyResolver(t, entries...)
}

// TestVerifyChain_SealersAndAssessments checks that a verified chain reports
// each set's sealer, recorded cv= and assessment, in instance order.
//
// checklist: ARC-RES-03
func TestVerifyChain_SealersAndAssessments(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	hops := threeHops("ARC body.\r\n")
	raw := buildHops(t, priv, hops)
	res := VerifyChain(context.Background(), []byte(raw), VerifyOptions{Resolver: hopsResolver(t, priv, hops)})
	if res.Status != "pass" {
		t.Fatalf("status = %s (%s), want pass", res.Status, res.Reason)
	}
	if cv, reason := Verify(context.Background(), []byte(raw), hopsResolver(t, priv, hops)); cv != res.Status || reason != res.Reason {
		t.Fatalf("Verify = %s (%s), VerifyChain = %s (%s)", cv, reason, res.Status, res.Reason)
	}
	if res.OldestPassChecked {
		t.Fatal("oldest-pass computed without being asked for")
	}
	want := []ChainSet{
		{
			Instance: 1, SealDomain: "origin.test", SealSelector: "s1", ChainValidation: "none",
			SignatureDomain: "origin.test", SignatureSelector: "ams1",
			AuthResults: hops[0].aar,
			Assessment: Assessment{AuthServID: "origin.test", Results: []MethodResult{
				{Method: "spf", Result: "pass", Properties: []Property{{"smtp", "mailfrom", "alice@example.test"}}},
				{Method: "dkim", Result: "pass", Properties: []Property{{"header", "d", "example.test"}}},
			}},
		},
		{
			Instance: 2, SealDomain: "list.test", SealSelector: "s2", ChainValidation: "pass",
			SignatureDomain: "list-ams.test", SignatureSelector: "ams2",
			AuthResults: hops[1].aar,
			Assessment: Assessment{AuthServID: "list.test", Results: []MethodResult{
				{Method: "dmarc", Result: "pass", Properties: []Property{{"header", "from", "example.test"}}},
				{Method: "arc", Result: "none"},
			}},
		},
		{
			Instance: 3, SealDomain: "forward.test", SealSelector: "s3", ChainValidation: "pass",
			SignatureDomain: "forward.test", SignatureSelector: "ams3",
			AuthResults: hops[2].aar,
			Assessment:  Assessment{AuthServID: "forward.test"},
		},
	}
	if !reflect.DeepEqual(res.Sets, want) {
		t.Fatalf("Sets =\n%+v\nwant\n%+v", res.Sets, want)
	}
}

// TestVerifyChain_SetsOnFailure checks when Sets is filled for a chain that
// fails: a chain that reads as complete sets but whose seal does not verify
// still names its sealers, and one too malformed to read names none.
//
// checklist: ARC-RES-03
func TestVerifyChain_SetsOnFailure(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	hops := threeHops("ARC body.\r\n")
	raw := buildHops(t, priv, hops)
	resolver := hopsResolver(t, priv, hops)

	broken := strings.Replace(raw, "cv=pass; b=", "cv=pass; b=AAAA", 1) // the i=3 seal
	res := VerifyChain(context.Background(), []byte(broken), VerifyOptions{Resolver: resolver, OldestPass: true})
	if res.Status != "fail" {
		t.Fatalf("broken seal: status = %s (%s), want fail", res.Status, res.Reason)
	}
	if res.OldestPassChecked || res.OldestPass != 0 {
		t.Fatalf("failing chain has oldest-pass %d (checked %v)", res.OldestPass, res.OldestPassChecked)
	}
	if len(res.Sets) != 3 || res.Sets[2].SealDomain != "forward.test" {
		t.Fatalf("broken seal: Sets = %+v, want the three sets", res.Sets)
	}

	incomplete := strings.Replace(raw, "ARC-Seal: i=2;", "X-Old-Seal: i=2;", 1)
	res = VerifyChain(context.Background(), []byte(incomplete), VerifyOptions{Resolver: resolver})
	if res.Status != "fail" || res.Sets != nil {
		t.Fatalf("incomplete set: %s (%s), Sets = %+v; want fail and no sets", res.Status, res.Reason, res.Sets)
	}

	res = VerifyChain(context.Background(), []byte(arcBaseMessage()), VerifyOptions{Resolver: resolver, OldestPass: true})
	if res.Status != "none" || res.Sets != nil || res.OldestPassChecked {
		t.Fatalf("no chain: %+v", res)
	}
}

// TestVerifyChain_OldestPass checks RFC 8617 §5.2 step 5 on chains whose
// older ARC-Message-Signatures break at different hops.
//
// checklist: ARC-VAL-08 ARC-RES-01
func TestVerifyChain_OldestPass(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	const (
		orig   = "ARC body.\r\n"
		footer = "ARC body.\r\nList footer.\r\n"
		second = "ARC body.\r\nList footer.\r\nForwarder note.\r\n"
	)
	for _, tc := range []struct {
		name   string
		bodies []string
		want   int
	}{
		{"one hop", []string{orig}, 0},
		{"three intact hops", []string{orig, orig, orig}, 0},
		{"first hop's AMS broken", []string{orig, footer, footer}, 2},
		{"first two hops' AMS broken", []string{orig, footer, second}, 3},
		// Step 5A stops at the first failure counting down, so an intact AMS
		// below a broken one does not lower the value.
		{"middle hop's AMS broken", []string{orig, footer, orig}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hops := threeHops("")[:len(tc.bodies)]
			for i := range hops {
				hops[i].body = tc.bodies[i]
			}
			raw := buildHops(t, priv, hops)
			res := VerifyChain(context.Background(), []byte(raw), VerifyOptions{Resolver: hopsResolver(t, priv, hops), OldestPass: true})
			if res.Status != "pass" {
				t.Fatalf("status = %s (%s), want pass", res.Status, res.Reason)
			}
			if !res.OldestPassChecked || res.OldestPass != tc.want {
				t.Fatalf("oldest-pass = %d (checked %v), want %d", res.OldestPass, res.OldestPassChecked, tc.want)
			}
		})
	}
}

// TestVerifyChain_OldestPassAMSRules checks that an older AMS is held to the
// rules of the most recent one: one that does not sign From fails it, even
// though its signature verifies, and a missing key fails it too.
//
// checklist: ARC-VAL-08
func TestVerifyChain_OldestPassAMSRules(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	headers, body := dkim.SplitMessage([]byte(arcBaseMessage()))
	first := &arcSet{
		aar: mkHeader("ARC-Authentication-Results", "i=1; example.test; none"),
		ams: mkHeader("ARC-Message-Signature", signAMSH(t, priv, "example.test", "arc", 1, "to:subject", headers, body)),
	}
	first.as = mkHeader("ARC-Seal", signAS(t, priv, "example.test", "arc", 1, "none", []*arcSet{first}))
	second := &arcSet{
		aar: mkHeader("ARC-Authentication-Results", "i=2; example.test; arc=pass"),
		ams: mkHeader("ARC-Message-Signature", signAMS(t, priv, "example.test", "arc", 2, headers, body)),
	}
	second.as = mkHeader("ARC-Seal", signAS(t, priv, "example.test", "arc", 2, "pass", []*arcSet{first, second}))
	raw := second.as.Raw + "\r\n" + second.ams.Raw + "\r\n" + second.aar.Raw + "\r\n" +
		first.as.Raw + "\r\n" + first.ams.Raw + "\r\n" + first.aar.Raw + "\r\n" + arcBaseMessage()
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	res := VerifyChain(context.Background(), []byte(raw), VerifyOptions{Resolver: resolver, OldestPass: true})
	if res.Status != "pass" || !res.OldestPassChecked || res.OldestPass != 2 {
		t.Fatalf("AMS without From: %s (%s), oldest-pass %d (checked %v); want pass, 2",
			res.Status, res.Reason, res.OldestPass, res.OldestPassChecked)
	}

	hops := threeHops("ARC body.\r\n")[:2]
	raw = buildHops(t, priv, hops)
	noOldKey := keyResolver(t,
		keyEntry{priv: priv, selector: "s1", domain: "origin.test"},
		keyEntry{priv: priv, selector: "s2", domain: "list.test"},
		keyEntry{priv: priv, selector: "ams2", domain: "list-ams.test"})
	res = VerifyChain(context.Background(), []byte(raw), VerifyOptions{Resolver: noOldKey, OldestPass: true})
	if res.Status != "pass" || res.OldestPass != 2 {
		t.Fatalf("retired AMS key: %s (%s), oldest-pass %d; want pass, 2", res.Status, res.Reason, res.OldestPass)
	}
}

// TestParseAssessment checks how an ARC-Authentication-Results payload is
// read as RFC 8601 results: comments dropped, quoted values kept whole,
// names lowercased, and a payload that does not parse read leniently.
//
// checklist: ARC-RES-03
func TestParseAssessment(t *testing.T) {
	for _, tc := range []struct {
		payload string
		want    Assessment
	}{
		{"example.com; none", Assessment{AuthServID: "example.com"}},
		{" (hop) example.com 1 (v1) ;\r\n spf=pass (sender ok) smtp.mailfrom=a@example.com",
			Assessment{AuthServID: "example.com", Results: []MethodResult{
				{Method: "spf", Result: "pass", Properties: []Property{{"smtp", "mailfrom", "a@example.com"}}},
			}}},
		{`example.com; DKIM/1 = Fail reason="bad; sig" header.D=example.com header.s="sel (x)"; dmarc=pass`,
			Assessment{AuthServID: "example.com", Results: []MethodResult{
				{Method: "dkim", Result: "fail", Reason: "bad; sig", Properties: []Property{{"header", "d", "example.com"}, {"header", "s", "sel (x)"}}},
				{Method: "dmarc", Result: "pass"},
			}}},
		{"this is not an Authentication-Results payload", Assessment{AuthServID: "this"}},
		{`"quoted id"; arc=pass (unclosed`, Assessment{AuthServID: "quoted id", Results: []MethodResult{{Method: "arc", Result: "pass"}}}},
		{`a.example; dkim=pass header.b="ab\"c;d" (nested (comment \) x) y) policy.x=1 stray`,
			Assessment{AuthServID: "a.example", Results: []MethodResult{
				{Method: "dkim", Result: "pass", Properties: []Property{{"header", "b", `ab"c;d`}, {"policy", "x", "1"}}},
			}}},
		{`example.com; =pass; "q"=pass; spf; dkim=pass nodot=x; spf=fail reason="unterminated\`,
			Assessment{AuthServID: "example.com", Results: []MethodResult{
				{Method: "dkim", Result: "pass"},
				{Method: "spf", Result: "fail", Reason: "unterminated"},
			}}},
		{"", Assessment{}},
	} {
		if got := parseAssessment(tc.payload); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseAssessment(%q) =\n%+v\nwant\n%+v", tc.payload, got, tc.want)
		}
	}
}
