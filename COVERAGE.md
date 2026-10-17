# Coverage exceptions

CI fails when statement coverage of `./...` falls below 95%. These are the
statements left uncovered on purpose, each with the reason. Add an entry here
whenever you leave a statement uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `arc.go` | `Verify` | `resolver = net.DefaultResolver.LookupTXT` | A nil resolver means the system's DNS; the tests never use the network. |
| `arc.go` | `Verify` | `return "fail", ...` when there are more than 50 sets | Unreachable today: `collectARCSets` refuses an instance above 50, so at most 50 distinct sets get this far. The check stays so that the limit holds even if instance parsing changes. |
| `seal.go` | `Seal` | `return nil, fmt.Errorf(...)` after signing the AMS and the AS | `signRSA` fails only if `rsa.SignPKCS1v15` does, which needs a key too small to hold a SHA-256 signature; `rsa.GenerateKey` and `dkim.ParsePrivateKey` produce no such key. |
| `seal.go` | `signRSA` | `return "", err` | As above. |
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover; CI also runs the command itself. |
