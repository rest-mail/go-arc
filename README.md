# arc

[![CI](https://github.com/rest-mail/arc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/arc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/arc.svg)](https://pkg.go.dev/github.com/rest-mail/arc)

ARC — Authenticated Received Chain
([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) — verification for Go.

ARC lets a message's authentication assessment survive intermediaries (mailing
lists, forwarders) that legitimately break DKIM and SPF. Each participating hop
adds an ARC set — `ARC-Authentication-Results`, `ARC-Message-Signature`,
`ARC-Seal` — and a downstream verifier can cryptographically confirm the whole
chain.

`arc.Verify` validates, over the **raw** message bytes:

1. chain structure — sets numbered contiguously `1..N`, each complete; and
2. cryptography (RFC 8617 §5.2) — the most recent `ARC-Message-Signature`
   verifies over the message, and every `ARC-Seal` verifies over the ARC header
   chain up to its instance.

An `ARC-Message-Signature` is structurally a DKIM-Signature and an `ARC-Seal` is
a DKIM-style signature over the ARC headers, so this package builds on the
canonicalization and signature primitives exported by
[github.com/rest-mail/dkim](https://github.com/rest-mail/dkim) — ARC
verification is therefore byte-for-byte consistent with DKIM verification over
the same message.

## Install

```sh
go get github.com/rest-mail/arc
```

## Verify

`arc.Verify` returns a chain-validation status (`"pass"`, `"fail"`, or
`"none"`) plus a human-readable reason. Pass `nil` for the resolver to use
system DNS, or inject a `dkim.TXTResolver` (its signature matches
`net.Resolver.LookupTXT`) in tests.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/arc"
)

func main() {
	raw := []byte( /* a raw message carrying ARC-* header sets */ )

	cv, reason := arc.Verify(context.Background(), raw, nil)
	fmt.Printf("arc=%s (%s)\n", cv, reason)
	// cv is "pass", "fail", or "none"; feed it into an
	// Authentication-Results header as arc=<cv>.
}
```

## License

[MIT](LICENSE) © 2026 rest-mail
