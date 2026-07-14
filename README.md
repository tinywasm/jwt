# tinywasm/jwt
<img src="docs/img/badges.svg">

Isomorphic **JWT (HS256)** for the tinywasm ecosystem: the same code signs and verifies
on the native backend and inside a WASM/edge binary (browser, Cloudflare Workers,
`goflare`).

It exists so a consumer that only needs to **verify** a token does not have to import an
entire auth stack (ORM, bcrypt, OAuth, a database driver) to do it.

```go
import "github.com/tinywasm/jwt"

secret := []byte("a-256-bit-secret")

token, err := jwt.Sign(secret, jwt.NewClaims(userID, 3600)) // ttl in seconds
if err != nil {
    return err
}

claims, err := jwt.Verify(secret, token)
switch err {
case nil:
    use(claims.Sub)
case jwt.ErrTokenExpired:
    // not an attack: the session ended, ask for a new login
case jwt.ErrInvalidToken:
    // malformed or unauthentic — do not tell the caller which
}
```

## Design

**HS256 only. No algorithm negotiation.** That is the security model, not a limitation.

`Verify` **never reads the `alg` field** of the token — it always recomputes HS256.
Choosing the algorithm from a value carried inside the untrusted token is the classic
alg-confusion vulnerability, and it is how `{"alg":"none"}` forgeries get accepted.

`Claims` is a closed struct (`Sub`, `Exp`, `Iat`), never a `map[string]any` bag.

The library refuses rather than returning something that merely looks fine:

| Refused | Why |
|---|---|
| empty secret | HMAC over an empty key is valid math — it mints tokens **anyone can forge** |
| empty subject | a token that authenticates nobody would let `""` through as an identity |
| token without `exp` | it is malformed, not eternal |
| any signature mismatch | compared in constant time (`crypto.HMACEqual`) |

`ErrTokenExpired` is deliberately distinct from `ErrInvalidToken`: expiry is not an
attack, and the caller must be able to tell "log in again" from "this is a forgery".
Every other failure collapses into `ErrInvalidToken` on purpose — distinguishing
"bad signature" from "bad base64" tells an attacker where they stand.

## Status

Signing and verifying are done and tested (native + WASM).

**Not yet usable from a frontend that has no secret**, and not yet proven to
interoperate with other JWT implementations. Both, plus clock-skew tolerance and key
rotation, are specified in [docs/PLAN.md](docs/PLAN.md).

## Testing

```bash
gotest          # both suites: native + wasm
gotest -tinygo  # compiles the WASM suite with TinyGo
```

See [AGENTS.md](AGENTS.md) for the constraints any change must respect.
