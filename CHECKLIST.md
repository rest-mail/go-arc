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

## Audit record (2026-10-22)

Read RFC 8617 section by section against this checklist and the implementation.
Every explicit MUST, MUST NOT and SHOULD in RFC 8617 was already represented;
this pass adds missing normative rules, permitted behaviour and host duties.
It does not claim a fresh clause-by-clause audit of the imported RFCs. As with
ARC-HDR-16, an unsupported rule is explicitly marked `n/a` with the limitation;
it is a conformance gap, not evidence that the RFC makes the rule optional.

| Sections audited | Result |
|------------------|--------|
| 1, 2.1–2.4, 3.1–3.8 | Introduction and definitions; added the §3.4 distinction between an authenticated assessment and its syntax/accuracy (ARC-HDR-18). |
| 3.9, 4.1, 4.1.1–4.1.4 | Rechecked every explicit keyword against ARC-HDR-01–17. Added independent signing identities, UTF-8 payload/message proof and explicit instance-grammar limitations (ARC-HDR-19–23). U-label identities remain ARC-HDR-16. |
| 4.2, 4.2.1, 4.3, 4.4 | Set membership, numbering, ordered chain and statuses remain ARC-SET-01–03 and ARC-VAL-01–06/10. No new keyword requirement. |
| 5, 5.1, 5.1.1–5.1.5 | Sealing order/scope remain ARC-SEAL-01–09; added a public-API no-restart proof for §5.1.3 (ARC-SEAL-10). The permission to seal unchanged mail (§5.1.4) and its safety (§5.1.5) are exercised by the existing single/two-hop round trips. Local-policy permission is ARC-POLICY-01. |
| 5.2, 5.2.1, 5.2.2 | Rechecked every step and keyword against ARC-VAL-01–16. Added proof that a failed older AMS does not fail the chain and that validation stops without unnecessary DNS (ARC-VAL-17–18). Oldest-pass remains deliberately unimplemented, pending owner decision (ARC-VAL-08). |
| 6 | Existing result/property SHOULDs remain ARC-VAL-11 and ARC-RES-01; added the `arc` method-name host duty (ARC-RES-02). |
| 7, 7.1, 7.1.1–7.1.3, 7.2, 7.2.1–7.2.2 | Use cases and local-policy/reporting permissions are host duties (ARC-POLICY-01–02). |
| 8, 9, 9.1–9.5 | Privacy/security discussion adds no explicit MUST/SHOULD. Content scanning, sealer reputation, DNS caching and replay policy belong to the host; a passing chain authenticates assertions, not message safety. |
| 10, 10.1–10.4 | Registry definitions correspond to existing header names, statuses, SMTP codes and result properties; the method name is now explicit in ARC-RES-02. No additional implementation keyword. |
| 11, 11.1–11.3, 11.3.1–11.3.4, 12, Appendices A–B | Experiment evaluation, references, design criteria and examples; no additional protocol MUST/SHOULD. No evaluation/reputation or reporting service is implemented here. |

## ARC header fields (§4.1, §4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-HDR-01 | 4.1.1 | Normative | An ARC-Authentication-Results field is `i=` and its instance, then `;`, then an Authentication-Results payload; one that does not start that way is malformed and fails the chain. | `TestRFC_MalformedFieldsFail` |
| ARC-HDR-02 | 4.1.1 | MUST | The AAR holds the combined results of every check the sealing ADMD made. The caller decides what it checked and passes the combined results in `SealOptions.AuthResults`; Seal records every one of them after the instance, under the ARC-Seal. | `TestSeal_RecordsCallerAuthResults` |
| ARC-HDR-03 | 4.1.2 | Normative | The ARC-Message-Signature has the syntax and semantics of a DKIM-Signature, and is verified with RFC 6376 §5's canonicalization, hashing and signature check. | `TestVerifyARC_SingleSetRoundTrip`, `TestVerifyARC_TamperedBodyFailsAMS`, `TestValiMailValidationSuite` |
| ARC-HDR-04 | 4.1.2 | MUST | A `v=` tag in an AMS is ignored. | `TestVerifyARC_AMSVersionTagIgnored`, `TestVerifyARC_AMSVersionTagStillFailsOnTamper` |
| ARC-HDR-05 | 4.1.2 | Normative | The AMS `i=` tag is the instance, not DKIM's AUID, so none of DKIM's AUID rules apply to it. | `TestVerifyARC_SingleSetRoundTrip`, `TestSeal_SingleSetRoundTrip` |
| ARC-HDR-06 | 4.1.2 | SHOULD | A sealer attaches the AMS so that the ADMD's own modifications are signed. | `TestSeal_SignsChangesMadeBeforeSealing` |
| ARC-HDR-07 | 4.1.2 | MUST NOT | A sealer does not list Authentication-Results in the AMS `h=` tag. | `TestAMSHeaderTag_ExcludesARCAndAuthResults`, `TestSeal_AMSHeaderTagExcludesInPractice` |
| ARC-HDR-08 | 4.1.2 | MUST NOT | A sealer does not list ARC-Authentication-Results, ARC-Message-Signature or ARC-Seal in the AMS `h=` tag. | `TestAMSHeaderTag_ExcludesARCAndAuthResults`, `TestSeal_AMSHeaderTagExcludesInPractice` |
| ARC-HDR-09 | 4.1.2 | MUST NOT | A validator fails a chain whose latest AMS signs an ARC-Seal or ARC-Message-Signature. One that signs an ARC-Authentication-Results, as draft-era sealers did, is tolerated. | `TestValiMailValidationSuite` |
| ARC-HDR-10 | 4.1.2 | SHOULD | The AMS signs the DKIM-Signature fields already on the message. | `TestSeal_SignsDKIMSignatures` |
| ARC-HDR-11 | RFC 6376 §5.4 | MUST | The AMS `h=` tag includes From; an AMS that does not sign From fails the chain. | `TestVerifyARC_AMSMustSignFrom`, `TestValiMailValidationSuite` |
| ARC-HDR-12 | 4.1.3 | Normative | The ARC-Seal covers no body (no `bh=`) and uses relaxed header canonicalization only. | `TestVerifyARC_SingleSetRoundTrip`, `TestSeal_SingleSetRoundTrip` |
| ARC-HDR-13 | 4.1.3 | MUST | An ARC-Seal carrying an `h=` tag makes the chain fail. | `TestVerifyARC_SealWithHTagRejected` |
| ARC-HDR-14 | 4.1.3 | Normative | An ARC-Seal names its key with `d=` and `s=`; one without either fails rather than falling back to a default selector. | `TestVerifyARC_SealMissingSelectorRejected` |
| ARC-HDR-15 | RFC 6376 §3.2 | Normative | AMS and AS tag-lists are read strictly: a repeated tag, a tag name outside the ABNF or an empty tag-spec makes the field malformed. Tag names are case-sensitive. Only SP, HTAB and CRLF folding count as whitespace (FWS), there and in `h=`. | `TestVerifyARC_DuplicateTagRejected`, `TestRFC_MalformedFieldsFail`, `FuzzFieldInstance`, `TestStrictTagList_OnlyFWSIsWhitespace` |
| ARC-HDR-16 | 4.1.4 | Normative | The `d=` and `s=` tags of ARC header fields may hold U-labels. | n/a: like go-dkim for the DKIM-Signature, go-arc accepts A-labels only, and a U-label `d=` or `s=` fails the chain. Converting needs IDNA tables the library does not carry; no sealer seen in practice writes U-labels. |
| ARC-HDR-17 | RFC 6376 §3.5 | Normative | The ARC-Seal's `d=` and `s=` are DNS names; anything else is not sent to the resolver and fails the chain. | `TestRFC_MalformedFieldsFail` |
| ARC-HDR-18 | 3.4 | Normative | The accuracy and syntax of the encapsulated authres-payload do not affect chain validity; an intact seal authenticates even a negative or syntactically invalid assessment, but a changed payload fails. | `TestRFC_AARPayloadIsOpaque` |
| ARC-HDR-19 | 4.1.2 | Normative | ARC imposes no selector/domain alignment requirement on an AMS: its signing identity can differ from the AS, AAR authserv-id and message author, and its own published key must verify it. | `TestRFC_IndependentSigningIdentities` |
| ARC-HDR-20 | 4.1.3 | Normative | ARC imposes no selector/domain alignment requirement on an AS: its key identity can differ from the corresponding AMS and author, and its own published key must verify it. | `TestRFC_IndependentSigningIdentities` |
| ARC-HDR-21 | 4.1.4 | Normative | The AAR permits UTF-8 where Authentication-Results does; EAI message headers and payload text are preserved and signed without requiring DKIM quoted-printable encoding. This does not cover U-label key identities (ARC-HDR-16). | `TestRFC_UTF8AssessmentAndMessage` |
| ARC-HDR-22 | 4.1.2, 4.1.3 | Normative | The AMS and AS ABNF puts the instance before the rest of the tag-list. | n/a: not enforced for AMS/AS; `fieldInstance` deliberately accepts an instance anywhere in their tag-lists for sealer interoperability. This is a grammar tolerance, not strict ABNF conformance; AAR's first-instance rule is enforced (ARC-HDR-01). |
| ARC-HDR-23 | 3.9, 4.1.1–4.1.3 | Normative | The instance grammar allows CFWS, including RFC 5322 comments, around its name, equals sign and value. | n/a: not supported yet; instance parsing trims folding whitespace only, and the shared DKIM tag-list parser does not implement comment-bearing ARC instance syntax. Comment support needs coordinated parsing of the instance prefix and signature tags; ordinary FWS is supported. |

## ARC Sets (§4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-SET-01 | 4.2.1 | Normative | An instance is a decimal from 1 to 50, written without sign or leading zero; any other `i=` makes the field malformed and the chain fail, not absent. | `TestVerifyARC_MalformedInstanceFailsNotNone`, `TestVerifyARC_OutOfRangeInstanceRejected`, `TestVerifyARC_ZeroPaddedInstanceRejected`, `FuzzFieldInstance` |
| ARC-SET-02 | 4.2.1 | MUST | An ARC Set has exactly one each of AAR, AMS and AS for its instance. | `TestVerifyARC_DuplicateFieldRejected`, `TestSeal_DuplicateIncomingChainRejected`, `TestSeal_IncompleteIncomingChainRejected` |
| ARC-SET-03 | 4.2.1 | Normative | Several signing algorithms at one instance ([ARC-MULTI]). | n/a: ARC-MULTI is an expired draft; a second field of a type at one instance fails the chain (ARC-SET-02). |

## Sealer (§5.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-SEAL-01 | 5.1 | MUST | Every change to the message, DKIM signing included, is made before sealing. The order is the caller's: it verifies on arrival, modifies, then seals with the arrival status in `SealOptions.ChainValidation`; the changes are signed and a later change fails the chain. | `TestSeal_SignsChangesMadeBeforeSealing` |
| ARC-SEAL-02 | 5.1 | Normative | Step 2: when the most recent ARC-Seal already says `cv=fail`, the sealer stops. | `TestSeal_StopsOnFailedChain` |
| ARC-SEAL-03 | 5.1 | Normative | Step 3: the new instance is one more than the highest on the message, or 1 when there is none. | `TestSeal_InstanceFromMaxNotCount`, `TestSeal_TwoHopChain`, `TestSeal_SingleSetRoundTrip` |
| ARC-SEAL-04 | 5.1 | Normative | Step 4: the sealer adds an AAR, an AMS and an AS, the AS carrying the chain validation status it found. | `TestSeal_SingleSetRoundTrip`, `TestSeal_TwoHopChain`, `TestSeal_BrokenIncomingChainRecordsFail`, `TestSeal_ChainValidationMustMatchTheChain` |
| ARC-SEAL-05 | 5.1.1 | Normative | The AS signs every ARC Set in increasing instance order, the new one included, each as AAR, AMS, AS, with its own `b=` empty. | `TestSeal_TwoHopChain`, `TestVerifyARC_TwoSetChain` |
| ARC-SEAL-06 | 5.1.2 | MUST | When the chain failed, the AS signs only the ARC Set being added. | `TestSeal_CVFailSealScope` |
| ARC-SEAL-07 | 4.2.1 | Normative | No ARC Set is added past instance 50. | `TestSeal_RefusesPastMaxInstance` |
| ARC-SEAL-08 | RFC 6376 §3.5 | Normative | The fields Seal writes are well formed: `d=` and `s=` are DNS names, and no input carries a CR or LF into a header field. | `TestSeal_RejectsCRLFInjection`, `TestSeal_RejectsInvalidDomainOrSelector`, `TestSeal_RequiredOptions` |
| ARC-SEAL-09 | RFC 8301 §3.1 | MUST | Signers use rsa-sha256, never rsa-sha1. | `TestSeal_SingleSetRoundTrip` |
| ARC-SEAL-10 | 5.1.3 | Normative | A broken chain cannot be restarted or continued: when the latest seal declares failure, Seal refuses to add another set even if the caller overrides the arrival status, and preserves the input. | `TestRFC_FailedChainCannotRestart` |

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
| ARC-VAL-17 | 5.2 step 5A | Normative | A failed older AMS does not affect chain validity when the latest AMS and all seals verify; historical AMS keys need not be fetched when oldest-pass is not computed. | `TestRFC_OlderAMSFailureDoesNotFailChain` |
| ARC-VAL-18 | 5.2 steps 1–4, 6 | Normative | Validation stops on absence or failure: structural/cv failures make no DNS queries, a failed latest AMS prevents seal lookups, and a failed latest seal prevents older seal lookups. | `TestRFC_ValidationStopsBeforeUnneededDNS` |
| ARC-RES-01 | 6 | SHOULD | Record `smtp.remote-ip` and `header.oldest-pass` with the `arc` result. | n/a: the caller writes Authentication-Results, and oldest-pass is not computed (ARC-VAL-08). |
| ARC-RES-02 | 6, 10.1 | Normative | Communicate chain-validation status in Authentication-Results and AAR using the authentication method name `arc` and result `none`, `pass` or `fail`. | n/a: the caller formats Authentication-Results and supplies the AAR payload; Verify exposes the three statuses but does not format a result header or insert a method into the caller's assessment. |

## Host policy and reporting (§5, §7)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| ARC-POLICY-01 | 5, 7.2.1 | MAY | A handler may use a validated chain's authentication assessments in local disposition decisions, including DMARC overrides. | n/a: the library verifies and seals; the receiver owns trust, DMARC evaluation and message disposition. A passing chain is not a trust or safety verdict. |
| ARC-POLICY-02 | 7.2.2 | MAY | A DMARC report may describe an ARC-influenced local-policy decision using reason `local_policy`; the comment includes at least the chain status, every AS domain/selector, and the originating IP from the first set. | n/a: this package creates no DMARC reports and has no SMTP connection metadata; the reporting host must obtain and format those data. |
