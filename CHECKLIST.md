# RFC 8617 checklist

Every requirement [RFC 8617](https://www.rfc-editor.org/rfc/rfc8617) places on
an ARC Validator and on an ARC Sealer, item by item, with the tests that cover
it. The list takes in every MUST, MUST NOT, SHOULD, SHOULD NOT, RECOMMENDED,
REQUIRED and OPTIONAL that applies to a validator or a sealer, and the
normative behaviour that carries no keyword (level "Normative"), such as the
steps of the validation algorithm in §5.2 and the header field grammar of
§4.1. The rules ARC imports from DKIM ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376),
updated by [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) and
[RFC 8463](https://www.rfc-editor.org/rfc/rfc8463)) are listed where ARC
relies on them. A section number alone is RFC 8617's; the others are named.

An item that does not apply to a library (because it is the receiver's policy,
or the library speaks no SMTP, say) says "n/a" and why. CI checks this file
against the tests with `go run ./internal/checklist`; the format is described
in the [README](README.md#the-rfc-checklist).

## ARC header fields (§4.1, §4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-HDR-01 | 4.1.1 | Normative | An ARC-Authentication-Results field is `i=` and its instance, then `;`, then an Authentication-Results payload; one that does not start that way is malformed and fails the chain. | `TestRFC_MalformedFieldsFail` |
| ARC-HDR-02 | 4.1.1 | MUST | The AAR holds the combined results of every check the sealing ADMD made. | n/a: the caller decides what it checked and passes the results in `SealOptions.AuthResults`; Seal records them as given. |
| ARC-HDR-03 | 4.1.2 | Normative | The ARC-Message-Signature has the syntax and semantics of a DKIM-Signature, and is verified with RFC 6376 §5's canonicalization, hashing and signature check. | `TestVerifyARC_SingleSetRoundTrip`, `TestVerifyARC_TamperedBodyFailsAMS`, `TestValiMailValidationSuite` |
| ARC-HDR-04 | 4.1.2 | MUST | A `v=` tag in an AMS is ignored. | `TestVerifyARC_AMSVersionTagIgnored`, `TestVerifyARC_AMSVersionTagStillFailsOnTamper` |
| ARC-HDR-05 | 4.1.2 | Normative | The AMS `i=` tag is the instance, not DKIM's AUID, so none of DKIM's AUID rules apply to it. | `TestVerifyARC_SingleSetRoundTrip`, `TestSeal_SingleSetRoundTrip` |
| ARC-HDR-06 | 4.1.2 | SHOULD | A sealer attaches the AMS so that the ADMD's own modifications are signed. | n/a: Seal signs the message it is given; the caller seals after its last change (see ARC-SEAL-01). |
| ARC-HDR-07 | 4.1.2 | MUST NOT | A sealer does not list Authentication-Results in the AMS `h=` tag. | `TestAMSHeaderTag_ExcludesARCAndAuthResults`, `TestSeal_AMSHeaderTagExcludesInPractice` |
| ARC-HDR-08 | 4.1.2 | MUST NOT | A sealer does not list ARC-Authentication-Results, ARC-Message-Signature or ARC-Seal in the AMS `h=` tag. | `TestAMSHeaderTag_ExcludesARCAndAuthResults`, `TestSeal_AMSHeaderTagExcludesInPractice` |
| ARC-HDR-09 | 4.1.2 | MUST NOT | A validator fails a chain whose latest AMS signs an ARC-Seal or ARC-Message-Signature. One that signs an ARC-Authentication-Results, as draft-era sealers did, is tolerated. | `TestValiMailValidationSuite` |
| ARC-HDR-10 | 4.1.2 | SHOULD | The AMS signs the DKIM-Signature fields already on the message. | `TestSeal_SignsDKIMSignatures` |
| ARC-HDR-11 | RFC 6376 §5.4 | MUST | The AMS `h=` tag includes From; an AMS that does not sign From fails the chain. | `TestVerifyARC_AMSMustSignFrom`, `TestValiMailValidationSuite` |
| ARC-HDR-12 | 4.1.3 | Normative | The ARC-Seal covers no body (no `bh=`) and uses relaxed header canonicalization only. | `TestVerifyARC_SingleSetRoundTrip`, `TestSeal_SingleSetRoundTrip` |
| ARC-HDR-13 | 4.1.3 | MUST | An ARC-Seal carrying an `h=` tag makes the chain fail. | `TestVerifyARC_SealWithHTagRejected` |
| ARC-HDR-14 | 4.1.3 | Normative | An ARC-Seal names its key with `d=` and `s=`; one without either fails rather than falling back to a default selector. | `TestVerifyARC_SealMissingSelectorRejected` |
| ARC-HDR-15 | RFC 6376 §3.2 | Normative | AMS and AS tag-lists are read strictly: a repeated tag, a tag name outside the ABNF or an empty tag-spec makes the field malformed. Tag names are case-sensitive. | `TestVerifyARC_DuplicateTagRejected`, `TestRFC_MalformedFieldsFail`, `FuzzFieldInstance` |
| ARC-HDR-16 | 4.1.4 | Normative | The `d=` and `s=` tags of ARC header fields may hold U-labels. | n/a: like go-dkim for the DKIM-Signature, go-arc accepts A-labels only, and a U-label `d=` or `s=` fails the chain. Converting needs IDNA tables the library does not carry; no sealer seen in practice writes U-labels. |
| ARC-HDR-17 | RFC 6376 §3.5 | Normative | The ARC-Seal's `d=` and `s=` are DNS names; anything else is not sent to the resolver and fails the chain. | `TestRFC_MalformedFieldsFail` |

## ARC Sets (§4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-SET-01 | 4.2.1 | Normative | An instance is a decimal from 1 to 50, written without sign or leading zero; any other `i=` makes the field malformed and the chain fail, not absent. | `TestVerifyARC_MalformedInstanceFailsNotNone`, `TestVerifyARC_OutOfRangeInstanceRejected`, `TestVerifyARC_ZeroPaddedInstanceRejected`, `FuzzFieldInstance` |
| ARC-SET-02 | 4.2.1 | MUST | An ARC Set has exactly one each of AAR, AMS and AS for its instance. | `TestVerifyARC_DuplicateFieldRejected`, `TestSeal_DuplicateIncomingChainRejected`, `TestSeal_IncompleteIncomingChainRejected` |
| ARC-SET-03 | 4.2.1 | Normative | Several signing algorithms at one instance ([ARC-MULTI]). | n/a: ARC-MULTI is an expired draft; a second field of a type at one instance fails the chain (ARC-SET-02). |

## Sealer (§5.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-SEAL-01 | 5.1 | MUST | Every change to the message, DKIM signing included, is made before sealing. | n/a: the order is the caller's; Seal signs the bytes it is given and the README says to seal last. |
| ARC-SEAL-02 | 5.1 | Normative | Step 2: when the most recent ARC-Seal already says `cv=fail`, the sealer stops. | `TestSeal_StopsOnFailedChain` |
| ARC-SEAL-03 | 5.1 | Normative | Step 3: the new instance is one more than the highest on the message, or 1 when there is none. | `TestSeal_InstanceFromMaxNotCount`, `TestSeal_TwoHopChain`, `TestSeal_SingleSetRoundTrip` |
| ARC-SEAL-04 | 5.1 | Normative | Step 4: the sealer adds an AAR, an AMS and an AS, the AS carrying the chain validation status it found. | `TestSeal_SingleSetRoundTrip`, `TestSeal_TwoHopChain`, `TestSeal_BrokenIncomingChainRecordsFail` |
| ARC-SEAL-05 | 5.1.1 | Normative | The AS signs every ARC Set in increasing instance order, the new one included, each as AAR, AMS, AS, with its own `b=` empty. | `TestSeal_TwoHopChain`, `TestVerifyARC_TwoSetChain` |
| ARC-SEAL-06 | 5.1.2 | MUST | When the chain failed, the AS signs only the ARC Set being added. | `TestSeal_CVFailSealScope` |
| ARC-SEAL-07 | 4.2.1 | Normative | No ARC Set is added past instance 50. | `TestSeal_RefusesPastMaxInstance` |
| ARC-SEAL-08 | RFC 6376 §3.5 | Normative | The fields Seal writes are well formed: `d=` and `s=` are DNS names, and no input carries a CR or LF into a header field. | `TestSeal_RejectsCRLFInjection`, `TestSeal_RejectsInvalidDomainOrSelector`, `TestSeal_RequiredOptions` |
| ARC-SEAL-09 | RFC 8301 §3.1 | MUST | Signers use rsa-sha256, never rsa-sha1. | `TestSeal_SingleSetRoundTrip` |

## Validator (§5.2, §6)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-VAL-01 | 5.2 | Normative | Step 1: a message with no ARC header fields has the status `none`. | `TestVerifyARC_NoChain`, `TestValiMailValidationSuite`, `FuzzVerify` |
| ARC-VAL-02 | 5.2 | Normative | Step 1: more than 50 ARC Sets is `fail`, before any other check. A chain of 50 can pass. | `TestVerifyARC_MaxSetsEnforced` |
| ARC-VAL-03 | 5.2 | Normative | Step 2: when the highest ARC Set's seal says `cv=fail`, the status is `fail`. | `TestVerifyARC_InconsistentCV`, `TestValiMailValidationSuite` |
| ARC-VAL-04 | 5.2 | MUST | Step 3A: each ARC Set has exactly one each of AAR, AMS and AS. | `TestVerifyARC_DuplicateFieldRejected`, `TestValiMailValidationSuite` |
| ARC-VAL-05 | 5.2 | MUST | Step 3B: the instances run 1 to N with no gap or repeat. | `TestSeal_InstanceFromMaxNotCount`, `TestValiMailValidationSuite` |
| ARC-VAL-06 | 5.2 | MUST | Step 3C: no seal says `cv=fail`; the seal at instance 1 says `none` and every later seal `pass`. | `TestVerifyARC_InconsistentCV`, `TestValiMailValidationSuite` |
| ARC-VAL-07 | 5.2 | Normative | Step 4: the AMS with the highest instance verifies, or the status is `fail`. | `TestVerifyARC_TamperedBodyFailsAMS`, `TestSeal_TamperedBodyFails`, `TestValiMailValidationSuite` |
| ARC-VAL-08 | 5.2 | OPTIONAL | Step 5: find the oldest AMS that still verifies (oldest-pass). | n/a: not computed; Verify returns the chain validation status and a reason. |
| ARC-VAL-09 | 5.2 | Normative | Step 6: every AS verifies, from instance N down to 1, or the status is `fail`. | `TestVerifyARC_TamperedSealFails`, `TestVerifyARC_WrongKeyFails`, `TestRFC_BrokenChainAtEachPosition`, `TestValiMailValidationSuite` |
| ARC-VAL-10 | 5.2 | Normative | Step 7: a chain that passes every step is `pass`, for chains of 1, 2 and the maximum of 50 sets. | `TestVerifyARC_SingleSetRoundTrip`, `TestVerifyARC_TwoSetChain`, `TestVerifyARC_MaxSetsEnforced` |
| ARC-VAL-11 | 5.2 | SHOULD | The result goes into the ADMD's Authentication-Results field. | n/a: the caller writes Authentication-Results; Verify returns the status for it. |
| ARC-VAL-12 | 5.2 | MUST | A chain that fails is treated like no chain at all. | n/a: delivery policy is the receiver's; the README says so. |
| ARC-VAL-13 | 5.2.1 | Normative | Every error, DNS failures included, is permanent and makes the status `fail`. | `TestRFC_DNSFailureIsFail` |
| ARC-VAL-14 | 5.2.2 | MAY | Reject a failing message in SMTP with 5.7.29 or 5.7.26. | n/a: the library speaks no SMTP. |
| ARC-VAL-15 | RFC 8301 §3.1 | MUST | rsa-sha1 signatures are not verified, in the AMS or the AS. | `TestRFC_MalformedFieldsFail` |
| ARC-VAL-16 | RFC 6376 §3.2 | Normative | Tag values are case-sensitive: an ARC-Seal with `a=RSA-SHA256` names no algorithm the validator knows. | `TestRFC_MalformedFieldsFail` |
| ARC-RES-01 | 6 | SHOULD | Record `smtp.remote-ip` and `header.oldest-pass` with the `arc` result. | n/a: the caller writes Authentication-Results, and oldest-pass is not computed (ARC-VAL-08). |
