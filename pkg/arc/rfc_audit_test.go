package arc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rest-mail/go-arc/pkg/arc/internal/grammar"
	"github.com/rest-mail/go-dkim/pkg/dkim"
)

// TestRFC_AARPayloadIsOpaque distinguishes authenticating an assessment from
// agreeing with it or parsing its methods (RFC 8617 §3.4). Even an assessment
// with invalid Authentication-Results syntax is covered by its seal.
//
// checklist: ARC-HDR-18
func TestRFC_AARPayloadIsOpaque(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	for _, payload := range []string{
		"example.test; spf=fail; dkim=fail; dmarc=fail",
		"example.test; spf=pass; spf=fail",
		"this is not an Authentication-Results payload",
	} {
		t.Run(payload, func(t *testing.T) {
			res, err := Seal(context.Background(), []byte(arcBaseMessage()), SealOptions{
				Domain: "example.test", Selector: "arc", PrivateKey: priv, AuthResults: payload,
			})
			if err != nil {
				t.Fatal(err)
			}
			if cv, reason := Verify(context.Background(), res.Message, resolver); cv != "pass" {
				t.Fatalf("intact assessment: %s (%s)", cv, reason)
			}
			changed := bytes.Replace(res.Message, []byte(payload), []byte(payload+" altered"), 1)
			if cv, reason := Verify(context.Background(), changed, resolver); cv != "fail" || !strings.Contains(reason, "ARC-Seal") {
				t.Fatalf("altered assessment: %s (%s), want seal failure", cv, reason)
			}
		})
	}
}

// TestRFC_IndependentSigningIdentities uses different keys, domains and
// selectors for AMS and AS, neither aligned with From nor the AAR authserv-id.
// RFC 8617 §4.1.2 and §4.1.3 impose no such alignment restriction.
//
// checklist: ARC-HDR-19 ARC-HDR-20
func TestRFC_IndependentSigningIdentities(t *testing.T) {
	amsKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	sealKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	base := arcBaseMessage()
	headers, body := dkim.SplitMessage([]byte(base))
	set := &arcSet{
		aar: mkHeader("ARC-Authentication-Results", "i=1; assessment.test; spf=pass"),
		ams: mkHeader("ARC-Message-Signature", signAMS(t, amsKey, "message.test", "msg", 1, headers, body)),
	}
	set.as = mkHeader("ARC-Seal", signAS(t, sealKey, "custodian.test", "seal", 1, "none", []*arcSet{set}))
	raw := []byte(set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n" + base)
	for _, tc := range []struct {
		name      string
		ams, seal *rsa.PrivateKey
		want      string
	}{
		{"independent identities", amsKey, sealKey, "pass"},
		{"wrong AMS key", sealKey, sealKey, "fail"},
		{"wrong AS key", amsKey, amsKey, "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := keyResolver(t,
				keyEntry{priv: tc.ams, selector: "msg", domain: "message.test"},
				keyEntry{priv: tc.seal, selector: "seal", domain: "custodian.test"})
			if cv, reason := Verify(context.Background(), raw, resolver); cv != tc.want {
				t.Fatalf("got %s (%s), want %s", cv, reason, tc.want)
			}
		})
	}
}

// TestRFC_UTF8AssessmentAndMessage preserves literal UTF-8 in an AAR payload
// and the signed message, without DKIM quoted-printable escaping (§4.1.4).
// U-label key identities remain the separate documented ARC-HDR-16 gap.
//
// checklist: ARC-HDR-21
func TestRFC_UTF8AssessmentAndMessage(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	base := strings.Replace(arcBaseMessage(), "Subject: arc round trip", "Subject: café 日本語", 1)
	base = strings.Replace(base, "ARC body.", "こんにちは café", 1)
	payload := `example.test; spf=pass reason="受信済み café" smtp.mailfrom="利用者@example.test"`
	res, err := Seal(context.Background(), []byte(base), SealOptions{
		Domain: "example.test", Selector: "arc", PrivateKey: priv, AuthResults: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.AAR, payload) || !bytes.HasSuffix(res.Message, []byte(base)) {
		t.Fatal("sealing changed literal UTF-8")
	}
	if cv, reason := Verify(context.Background(), res.Message, resolver); cv != "pass" {
		t.Fatalf("UTF-8 round trip: %s (%s)", cv, reason)
	}
	for _, tc := range []struct{ old, new, failure string }{
		{"受信済み", "変更済み", "ARC-Seal"},
		{"Subject: café", "Subject: thé", "ARC-Message-Signature"},
		{"こんにちは", "こんばんは", "ARC-Message-Signature"},
	} {
		t.Run(tc.failure+tc.old, func(t *testing.T) {
			changed := bytes.Replace(res.Message, []byte(tc.old), []byte(tc.new), 1)
			if cv, reason := Verify(context.Background(), changed, resolver); cv != "fail" || !strings.Contains(reason, tc.failure) {
				t.Fatalf("changed UTF-8: %s (%s), want %s failure", cv, reason, tc.failure)
			}
		})
	}
}

// TestRFC_OlderAMSFailureDoesNotFailChain proves §5.2 step 5A without
// implementing oldest-pass: the older AMS fails over the delivered body and
// its key has disappeared, but the latest AMS and all seals still verify.
//
// checklist: ARC-VAL-17
func TestRFC_OlderAMSFailureDoesNotFailChain(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	original := arcBaseMessage()
	modified := strings.Replace(original, "ARC body.", "Mailing list footer added.", 1)
	headers, oldBody := dkim.SplitMessage([]byte(original))
	_, newBody := dkim.SplitMessage([]byte(modified))
	first := &arcSet{
		aar: mkHeader("ARC-Authentication-Results", "i=1; example.test; spf=pass"),
		ams: mkHeader("ARC-Message-Signature", signAMS(t, priv, "example.test", "retired", 1, headers, oldBody)),
	}
	first.as = mkHeader("ARC-Seal", signAS(t, priv, "example.test", "seal", 1, "none", []*arcSet{first}))
	second := &arcSet{
		aar: mkHeader("ARC-Authentication-Results", "i=2; example.test; arc=pass"),
		ams: mkHeader("ARC-Message-Signature", signAMS(t, priv, "example.test", "latest", 2, headers, newBody)),
	}
	second.as = mkHeader("ARC-Seal", signAS(t, priv, "example.test", "seal", 2, "pass", []*arcSet{first, second}))
	// Check the premise independently with the retired key still available.
	oldResolver := testKeyResolver(t, publicPEM(t, priv), "retired", "example.test")
	if result := dkim.VerifySignatureBare(context.Background(), *first.ams, headers, oldBody, oldResolver); result.Result != dkim.ResultPass {
		t.Fatalf("older AMS did not verify on arrival: %+v", result)
	}
	if result := dkim.VerifySignatureBare(context.Background(), *first.ams, headers, newBody, oldResolver); result.Result != dkim.ResultFail || result.Reason != "body hash mismatch" {
		t.Fatalf("older AMS over modified body: %+v, want body hash mismatch", result)
	}
	resolver := keyResolver(t,
		keyEntry{priv: priv, selector: "latest", domain: "example.test"},
		keyEntry{priv: priv, selector: "seal", domain: "example.test"})
	var queries []string
	tracked := func(ctx context.Context, name string) ([]string, error) {
		queries = append(queries, name)
		return resolver(ctx, name)
	}
	raw := second.as.Raw + "\r\n" + second.ams.Raw + "\r\n" + second.aar.Raw + "\r\n" +
		first.as.Raw + "\r\n" + first.ams.Raw + "\r\n" + first.aar.Raw + "\r\n" + modified
	if cv, reason := Verify(context.Background(), []byte(raw), tracked); cv != "pass" {
		t.Fatalf("chain with invalid historical AMS: %s (%s)", cv, reason)
	}
	want := []string{"latest._domainkey.example.test", "seal._domainkey.example.test", "seal._domainkey.example.test"}
	if !slices.Equal(queries, want) {
		t.Fatalf("key lookups = %v, want %v (no retired AMS lookup)", queries, want)
	}
}

// TestRFC_FailedChainCannotRestart checks §5.1.3 through the public sealer:
// even an explicit caller override cannot continue a chain marked cv=fail.
//
// checklist: ARC-SEAL-10
func TestRFC_FailedChainCannotRestart(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	opts := SealOptions{Domain: "example.test", Selector: "arc", PrivateKey: priv, Resolver: resolver}
	first, err := Seal(context.Background(), []byte(arcBaseMessage()), opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.ChainValidation = "fail"
	failed, err := Seal(context.Background(), first.Message, opts)
	if err != nil {
		t.Fatal(err)
	}
	if cv, reason := Verify(context.Background(), failed.Message, resolver); cv != "fail" {
		t.Fatalf("failed-chain precondition: %s (%s)", cv, reason)
	}
	snapshot := bytes.Clone(failed.Message)
	for _, override := range []string{"", "none", "pass", "fail"} {
		t.Run(fmt.Sprintf("override=%q", override), func(t *testing.T) {
			opts.ChainValidation = override
			res, err := Seal(context.Background(), failed.Message, opts)
			if !errors.Is(err, ErrChainFailed) || res != nil {
				t.Fatalf("got result=%v error=%v, want no set and ErrChainFailed", res, err)
			}
			if !bytes.Equal(failed.Message, snapshot) {
				t.Fatal("refused sealing mutated the failed chain")
			}
		})
	}
}

// TestRFC_ValidationStopsBeforeUnneededDNS checks the stop instructions in
// §5.2 steps 1–4 and 6. Failures cannot cause lookups of older signers after
// the chain is already known to fail.
//
// checklist: ARC-VAL-18
func TestRFC_ValidationStopsBeforeUnneededDNS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	valid := sealChain(t, priv, "example.test", "arc", 2)
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	for _, tc := range []struct {
		name, raw, want string
		queries         int
	}{
		{"absent", arcBaseMessage(), "none", 0},
		{"incomplete", "ARC-Seal: i=1; cv=none\r\n" + arcBaseMessage(), "fail", 0},
		{"duplicate", "ARC-Authentication-Results: i=1; duplicate.test; none\r\n" + valid, "fail", 0},
		{"gap", gappedChain(t, priv, "example.test", "arc", 1, 3), "fail", 0},
		{"highest failed", sealChainCV(t, priv, "example.test", "arc", []string{"none", "fail"}), "fail", 0},
		{"inconsistent cv", sealChainCV(t, priv, "example.test", "arc", []string{"pass", "pass"}), "fail", 0},
		{"latest AMS", strings.Replace(valid, "Subject: arc round trip", "Subject: tampered", 1), "fail", 1},
		{"latest seal", sealChainBadSeal(t, priv, other, 3), "fail", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			tracked := func(ctx context.Context, name string) ([]string, error) {
				queries++
				return resolver(ctx, name)
			}
			if cv, reason := Verify(context.Background(), []byte(tc.raw), tracked); cv != tc.want {
				t.Fatalf("got %s (%s), want %s", cv, reason, tc.want)
			}
			if queries != tc.queries {
				t.Errorf("%d DNS queries, want %d", queries, tc.queries)
			}
		})
	}
}

// TestRFC_AARInstanceCFWS reads the AAR instance through the CFWS RFC 8617
// §3.9 and §4.1.1 allow around its name, "=", value and the ";" after it:
// folding whitespace and RFC 5322 comments, nested or holding quoted-pairs.
// An unclosed comment, or anything other than CFWS between the parts, is
// still malformed.
//
// checklist: ARC-HDR-23
func TestRFC_AARInstanceCFWS(t *testing.T) {
	for _, value := range []string{
		"i=1 (first hop); example.test; spf=pass",
		"(hop) i=1; example.test",
		"i (tag) = (value) 1 (end) ; example.test",
		"i=(a (nested) comment)1; example.test",
		`i=1 (quoted \) and \( parens); example.test`,
		"i=1 (has; a semicolon); example.test",
		"\r\n (folded\r\n comment)\r\n i=1; example.test",
	} {
		if n, err := grammar.Instance("arc-authentication-results", value); err != nil || n != 1 {
			t.Errorf("%q: got %d, %v; want instance 1", value, n, err)
		}
	}
	for _, value := range []string{
		"i=1 (unclosed; example.test",
		"(unclosed i=1; example.test",
		`i=1 (escaped close\); example.test`,
		"i=1 x; example.test",
		"i=1 (c) x; example.test",
		"i (c) x=1; example.test",
		"isp.example; i=1",
		"i=(c); example.test",
		"i=0 (c); example.test",
		"i=1 (c)",
	} {
		if n, err := grammar.Instance("arc-authentication-results", value); err == nil {
			t.Errorf("%q: got instance %d, want an error", value, n)
		}
	}

	// In a whole chain, a commented instance gets past the AAR grammar check:
	// the chain then fails only because the seal no longer covers the field.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	raw := sealChain(t, priv, "example.test", "arc", 1)
	for _, tc := range []struct{ new, reason string }{
		{"ARC-Authentication-Results: i=1 (first hop);", "ARC-Seal"},
		{"ARC-Authentication-Results: i=1 (first hop;", "unclosed comment"},
	} {
		changed := strings.Replace(raw, "ARC-Authentication-Results: i=1;", tc.new, 1)
		if changed == raw {
			t.Fatal("fixture has no AAR to change")
		}
		if cv, reason := Verify(context.Background(), []byte(changed), resolver); cv != "fail" || !strings.Contains(reason, tc.reason) {
			t.Errorf("%q: got %s (%s), want fail naming %q", tc.new, cv, reason, tc.reason)
		}
	}
}

// TestRFC_AMSASInstanceCFWS proves the leading instance of an
// ARC-Message-Signature and an ARC-Seal reads CFWS, including nested comments
// with quoted-pairs, around its name, equals sign and value (RFC 8617 §3.9,
// §4.1.2, §4.1.3), and that the rest of the field is still the strict tag-list.
//
// checklist: ARC-HDR-24
func TestRFC_AMSASInstanceCFWS(t *testing.T) {
	for _, name := range []string{"arc-message-signature", "arc-seal"} {
		for _, value := range []string{
			"i=1; a=rsa-sha256",
			"i=1 (first hop); a=rsa-sha256",
			"(hop) i=1; a=rsa-sha256",
			"i (tag) = (value) 1 (end) ; a=rsa-sha256",
			"i=(a (nested) comment)1; a=rsa-sha256",
			`i=1 (quoted \) and \( parens); a=rsa-sha256`,
			"i=1 (has; a semicolon); a=rsa-sha256",
			"\r\n (folded\r\n comment)\r\n i=1; a=rsa-sha256",
			"a=rsa-sha256; i=1",
		} {
			if n, err := grammar.Instance(name, value); err != nil || n != 1 {
				t.Errorf("%s %q: got %d, %v; want instance 1", name, value, n, err)
			}
		}
		for _, value := range []string{
			"(hop) i=1; a=rsa-sha256; i=1",
			"(hop) i=1;; a=rsa-sha256",
			"(hop) i=1; (c) a=rsa-sha256",
			"(hop) i=1; a=rsa-sha256; a=rsa-sha256",
			"(hop) i=0; a=rsa-sha256",
			"(hop) i=01; a=rsa-sha256",
			"(unclosed i=1; a=rsa-sha256",
			"i=1 (c) x; a=rsa-sha256",
			"a=rsa-sha256; i=1 (c)",
		} {
			if n, err := grammar.Instance(name, value); err == nil {
				t.Errorf("%s %q: got instance %d, want an error", name, value, n)
			}
		}
	}

	// In whole chains signed over the commented bytes: every comment position
	// verifies in the ARC-Seal. The AMS signature is checked by go-dkim, whose
	// RFC 6376 §3.2 tag-list has no comments, so a comment after the equals
	// sign or the value verifies but one before the name or the equals sign
	// fails the chain at the AMS.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testKeyResolver(t, publicPEM(t, priv), "arc", "example.test")
	for _, tc := range []struct{ ams, as, want, reason string }{
		{"i=1", "(hop) i (x)= (y) 1 (z)", "pass", ""},
		{"i= (x) 1 (y)", "\r\n (folded\r\n comment)\r\n i=1", "pass", ""},
		{"i=1", `i=(a (nested \) ) comment)1`, "pass", ""},
		{"(hop) i=1", "i=1", "fail", "ARC-Message-Signature"},
		{"i (x)=1", "i=1", "fail", "ARC-Message-Signature"},
	} {
		raw := sealSingleInstanceText(t, priv, "example.test", "arc", tc.ams, tc.as)
		cv, reason := Verify(context.Background(), []byte(raw), resolver)
		if cv != tc.want || !strings.Contains(reason, tc.reason) {
			t.Errorf("AMS %q, AS %q: got %s (%s), want %s naming %q", tc.ams, tc.as, cv, reason, tc.want, tc.reason)
		}
	}
}

// sealSingleInstanceText builds a single-set ARC message whose AMS and AS
// start with the given instance text, signing every signature over exactly
// those bytes.
func sealSingleInstanceText(t *testing.T, priv *rsa.PrivateKey, d, s, amsInstance, asInstance string) string {
	t.Helper()
	base := arcBaseMessage()
	msgHeaders, body := dkim.SplitMessage([]byte(base))

	bh := base64.StdEncoding.EncodeToString(dkim.HashBytes(crypto.SHA256, []byte(dkim.CanonicalizeBody(body, "relaxed"))))
	hTag := "from:to:subject:date:message-id"
	amsNoB := fmt.Sprintf("%s; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=", amsInstance, d, s, hTag, bh)
	amsHdr := dkim.Header{Name: "ARC-Message-Signature", Value: " " + amsNoB, Raw: "ARC-Message-Signature: " + amsNoB}
	amsSig := signBase64(t, priv, dkim.BuildSignedHeaders(hTag, msgHeaders, amsHdr, "relaxed"))
	ams := mkHeader("ARC-Message-Signature", amsNoB+amsSig)
	aar := mkHeader("ARC-Authentication-Results", "i=1; example.test; spf=pass")

	set := &arcSet{aar: aar, ams: ams}
	chain := []*arcSet{set}
	asNoB := fmt.Sprintf("%s; a=rsa-sha256; d=%s; s=%s; t=1784776000; cv=none; b=", asInstance, d, s)
	set.as = mkHeader("ARC-Seal", asNoB)
	asSig := signBase64(t, priv, arcSealBase(chain))
	set.as = mkHeader("ARC-Seal", asNoB+asSig)

	return set.as.Raw + "\r\n" + set.ams.Raw + "\r\n" + set.aar.Raw + "\r\n" + base
}
