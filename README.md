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

claims, outcome, err := jwt.Verify(secret, token)
if err != nil {
    return err // YOU are broken (empty secret) — a config bug, not a bad token
}
switch outcome {
case jwt.Valid:
    use(claims.Sub)
case jwt.Expired:
    // not an attack: the session simply ended, ask for a new login
case jwt.Forged:
    // unauthentic — raise the alarm
}
```

The two return channels mean different things, and that separation **is** the API:

| Channel | Means | Example |
|---|---|---|
| `error` | **the caller** is broken | empty secret — a configuration bug |
| `Outcome` | what **the token** is | `Valid`, `Expired`, `Forged` |

### Frontend / Unverified Decode

If you are on the frontend (browser) or an edge worker without access to the secret,
you can still read the claims to show the user's name or know when the session expires:

```go
claims, err := jwt.DecodeUnverified(token)
if err == nil {
    fmt.Println("Expires at:", claims.Exp)
}
```

**Warning:** `DecodeUnverified` does NOT check the signature. Treat the result as a
display hint, never as an authorization decision.

An expired token is not an error: it is `Verify` working correctly. Keeping expiry out
of the `error` channel is what stops a caller writing `if err != nil { alarm() }` and
reporting every routine session expiry as a forgery — which is exactly the bug this
library was extracted to fix.

`Forged` is the **zero value**: an unset verdict denies.

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

`Forged` does **not** say *why*: distinguishing "bad signature" from "bad base64" tells
an attacker where they stand. And no outcome other than `Valid` returns usable claims —
an expired or forged token authorizes nobody, so handing its subject back would only
invite a caller to use it.

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
