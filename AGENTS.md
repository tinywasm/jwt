# Agent Guide — `tinywasm/jwt`

Constraints for agents working on this library. Read this before any change.

---

## What this library is

An **isomorphic** JWT layer: the same API compiles and behaves identically on the
native backend (standard Go) and on the frontend/edge (WebAssembly via TinyGo —
browsers, Cloudflare Workers, `goflare`).

It exists so that a consumer that only needs to **verify** a token — an edge worker, a
WASM frontend reading its own session — does not have to import an entire auth stack
(ORM, bcrypt, OAuth, a database driver) to do it. **Binary size is a design
constraint, not a detail.**

The canonical consumer is `tinywasm/user`, which issues the tokens this library signs.

## Public API shape — direct package functions

Stateless, package-level functions (`jwt.Sign`, `jwt.Verify`, `jwt.NewClaims`). **No**
constructor, **no** config struct, **no** receiver: this library is pure math over its
arguments and holds no state.

- **Typed over `any`** — zero generics, zero `any`, zero `map` in the public API.
- `Claims` is a **closed struct**, never a `map[string]any` bag. A claims bag is how
  JWT libraries grow holes: it moves validation from the compiler to the caller's
  memory. If a new registered claim is genuinely needed, add a **field**.
- **Minimal public surface** — export only what consumers call. Helpers stay
  unexported.

### Never export a "sign arbitrary header/payload" helper

The signing input is built **inside** `Sign`, from a header this library controls. A
caller-chosen header is exactly where algorithm confusion begins. Tests may forge
tokens by computing the MAC themselves (see `tests/shared_test.go`); the **API must
not make forging easy**.

## The security invariants — do not "simplify" these

1. **`Verify` never reads the `alg` field of the token.** It always recomputes HS256.
   Selecting the algorithm from a value carried *inside the untrusted token* is the
   classic alg-confusion vulnerability — it is how `{"alg":"none"}` forgeries get
   accepted. Reading the header to "validate" `alg` is not an improvement; not reading
   it at all is the fix. There is a regression test (`RejectsAlgNone`); if it starts
   failing, the code is wrong, not the test.
2. **An empty secret is refused, in both directions.** HMAC over an empty key is valid
   math: it mints a token that verifies. Accepting it would let a zero-value config
   produce tokens anyone can forge, with nothing looking wrong.
3. **An empty subject is refused.** A token that authenticates nobody would let `""`
   through as an identity, and `""` is the anonymous user across this ecosystem.
4. **A token without `exp` is invalid, not eternal.**
5. **Nothing is decoded before the signature is verified.** Never parse what you have
   not authenticated.
6. **The MAC comparison is constant-time** (`crypto.HMACEqual`). A `==`, a
   `bytes.Equal`, or an early return on the first differing byte is a **timing
   oracle** and will be rejected in review.
7. **`ErrTokenExpired` stays distinct from `ErrInvalidToken`.** Expiry is not an
   attack: the caller must be able to tell "log in again" from "this is a forgery".
   Every *other* failure collapses into `ErrInvalidToken` on purpose — telling "bad
   signature" apart from "bad base64" tells an attacker where they stand.

## The stdlib rule

**No Go stdlib.** Everything here reaches a WASM binary. Use the ecosystem packages:

| Instead of | Use |
|---|---|
| `strings`, `strconv`, `errors`, `fmt` | `github.com/tinywasm/fmt` |
| `encoding/json` | `github.com/tinywasm/json` |
| `encoding/base64` | `github.com/tinywasm/base64` |
| `time` | `github.com/tinywasm/time` (nanoseconds) |
| `crypto/hmac`, `crypto/sha256` | `github.com/tinywasm/crypto` |

**Never roll your own primitive.** No hand-written HMAC or SHA loops — call
`tinywasm/crypto`, which is the one place crypto stdlib is concentrated.

There is **no carve-out** in this repo. If you need something that is not in the table,
it belongs upstream in the corresponding `tinywasm/*` library, not here: **STOP and
report it** rather than working around it locally.

## Testing — dual WASM/stdlib pattern

```bash
go install github.com/tinywasm/devflow/cmd/gotest@latest
gotest          # runs BOTH suites: native + wasm
gotest -tinygo  # compiles the WASM suite with TinyGo (slow, goes through LLVM)
```

`gotest`, never `go test`.

**Plain `gotest` cannot prove TinyGo compatibility.** It builds the WASM suite with the
*Go* toolchain, whose backend supports the full stdlib — so a package TinyGo would
reject still shows a green `wasm ✅`. **Any change that adds or removes an import must
be checked with `gotest -tinygo`.**

All tests live in `tests/` and follow the mandatory dual-entry pattern:

1. Every test is a `test_XxxYyy` function registered inside `RunJWTTests` in
   `tests/shared_test.go`.
2. Two thin entry points delegate to it:
   - `tests/backStlib_test.go` (`//go:build !wasm`) → `TestJWT_Native`
   - `tests/frontWasm_test.go` (`//go:build wasm`) → `TestJWT_WASM`

**A bare top-level `TestXxx` runs in only one of the two environments** — which for a
library whose entire promise is isomorphism means the bug ships. Register it in
`RunJWTTests`.

Stdlib assertions only (`testing`); no assertion library, no mocks.

## Never

- Never call `gopush` or `codejob` — local developer tooling, outside the agent.
- Never change the token format or the signing input without it being ordered by
  `docs/PLAN.md`: consumers hold **already-issued tokens**, and a silent format change
  logs every user out (or, worse, silently accepts what it should not).
- Never widen the algorithm set "for compatibility". HS256-only is the security model,
  not a limitation waiting to be lifted.
