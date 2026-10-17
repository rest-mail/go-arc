package arc

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The ValiMail ARC test suite (https://github.com/ValiMail/arc_test_suite, MIT,
// commit f137dcb) is the public conformance suite OpenARC and dkimpy run. Its
// validation tests are kept unchanged in testdata/valimail-arc-test-suite with
// their licence. Its signing tests are left out: they compare header text byte
// for byte in dkimpy's tag order, which Seal does not write. The suite was
// written against draft 18 of the ARC protocol, so a few scenarios expect what
// RFC 8617 or RFC 8301 later changed; those are listed in
// suiteValidationExceptions with the reason.
const suiteDir = "testdata/valimail-arc-test-suite/"

// suiteScenario is one YAML document of the suite: the tests it holds and the
// DNS records they share.
type suiteScenario struct {
	Description string            `yaml:"description"`
	Tests       yaml.Node         `yaml:"tests"`
	TXTRecords  map[string]string `yaml:"txt-records"`
}

// suiteTest is one validation test of a scenario.
type suiteTest struct {
	Spec        string `yaml:"spec"`
	Description string `yaml:"description"`
	Message     string `yaml:"message"`
	CV          string `yaml:"cv"`
}

// namedTest is one test of a scenario under its name.
type namedTest struct {
	name string
	suiteTest
}

// tests returns a scenario's tests in file order. The suite repeats four test
// names in one scenario (as_fields_b_head_case, for example), which PyYAML
// reads as the last one only; every one is kept here, the repeat named with a
// "#2" suffix.
func (s suiteScenario) tests(t *testing.T) []namedTest {
	t.Helper()
	var out []namedTest
	seen := map[string]bool{}
	for i := 0; i+1 < len(s.Tests.Content); i += 2 {
		var tc suiteTest
		if err := s.Tests.Content[i+1].Decode(&tc); err != nil {
			t.Fatal(err)
		}
		name := s.Tests.Content[i].Value
		if seen[name] {
			name += "#2"
		}
		seen[name] = true
		out = append(out, namedTest{name, tc})
	}
	return out
}

// loadSuite reads every scenario of one suite file.
func loadSuite(t *testing.T, name string) []suiteScenario {
	t.Helper()
	data, err := os.ReadFile(suiteDir + name)
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []suiteScenario
	for {
		var s suiteScenario
		if err := dec.Decode(&s); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, s)
	}
	return out
}

// suiteMessage turns a suite message, written with LF line ends, into the CRLF
// form a message has on the wire.
func suiteMessage(m string) []byte {
	return []byte(strings.ReplaceAll(m, "\n", "\r\n"))
}

// suiteResolver serves a scenario's TXT records and NXDOMAINs everything else.
func suiteResolver(records map[string]string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, name string) ([]string, error) {
		if txt, ok := records[strings.TrimSuffix(name, ".")]; ok {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

// suiteException is a suite test whose expected status this library does not
// share: the status it returns instead, and why.
type suiteException struct {
	want   string
	reason string
}

// suiteValidationExceptions lists the validation tests that expect what draft
// 18 allowed but RFC 8617, RFC 6376 or RFC 8301 do not, by test name.
var suiteValidationExceptions = map[string]suiteException{
	"cv_fail_i1_as_cv_fail":     {"fail", "the suite gives no cv; the latest ARC-Seal says cv=fail, so the chain fails (RFC 8617 §5.2 step 2)"},
	"cv_fail_i2_as2_fail":       {"fail", "the suite gives no cv; the latest ARC-Seal says cv=fail, so the chain fails (RFC 8617 §5.2 step 2)"},
	"cv_fail_i2_as1_fail":       {"fail", "the suite gives no cv; an ARC-Seal says cv=fail, so the chain fails (RFC 8617 §5.2 step 3C)"},
	"ams_fields_c_na":           {"fail", "with no c= the AMS is simple/simple (RFC 6376 §3.5); the suite signed it relaxed, as draft ARC required"},
	"ams_fields_h_empty":        {"fail", "an AMS that does not sign From does not bind the author (RFC 6376 §5.4)"},
	"ams_fields_h_includes_ams": {"fail", "the AMS MUST NOT sign ARC header fields (RFC 8617 §4.1.2); the suite already fails one that signs an ARC-Seal"},
}

// TestValiMailValidationSuite runs every validation scenario of the ValiMail
// suite and compares the chain validation status with the expected one.
//
// checklist: ARC-HDR-03 ARC-HDR-09 ARC-HDR-11 ARC-VAL-01 ARC-VAL-03 ARC-VAL-04 ARC-VAL-05 ARC-VAL-06 ARC-VAL-07 ARC-VAL-09
func TestValiMailValidationSuite(t *testing.T) {
	scenarios := loadSuite(t, "arc-draft-validation-tests.yml")
	total := 0
	for _, sc := range scenarios {
		resolver := suiteResolver(sc.TXTRecords)
		for _, tc := range sc.tests(t) {
			total++
			t.Run(tc.name, func(t *testing.T) {
				want := strings.ToLower(strings.TrimSpace(tc.CV))
				if ex, ok := suiteValidationExceptions[tc.name]; ok {
					t.Logf("expecting cv=%s, not the suite's %q: %s", ex.want, tc.CV, ex.reason)
					want = ex.want
				}
				got, reason := Verify(context.Background(), suiteMessage(tc.Message), resolver)
				if got != want {
					t.Errorf("%s: cv=%s (%s), want %s", tc.Description, got, reason, want)
				}
			})
		}
	}
	t.Logf("%d validation tests", total)
}
