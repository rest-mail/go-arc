// Package grammar reads the syntax of the three ARC header fields
// (RFC 8617 §4.1): the instance tag of an ARC-Authentication-Results,
// ARC-Message-Signature or ARC-Seal, with the CFWS RFC 8617 §3.9 allows around
// a leading instance, and the strict RFC 6376 §3.2 tag-list the
// ARC-Message-Signature and ARC-Seal share with DKIM.
//
// Instance returns a field's instance, IsARCField recognises the three field
// names, and TrimFWS removes the folding whitespace a tag-list allows and
// nothing else. The package is internal to go-arc: the verifier and the
// sealer in package arc are its only users.
package grammar
