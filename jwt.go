// Package jwt signs and verifies JSON Web Tokens (HS256) isomorphically: the same
// code runs on the native backend and inside a WASM/edge binary.
//
// The library is deliberately small and closed: HS256 only, one claim set, no
// algorithm negotiation. See docs/ARCHITECTURE.md for why.
package jwt

import (
	"github.com/tinywasm/base64"
	"github.com/tinywasm/crypto"
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/json"
	"github.com/tinywasm/model"
	"github.com/tinywasm/time"
)

var (
	// ErrInvalidToken covers every malformed or unauthentic token: wrong shape, bad
	// signature, undecodable payload. It is deliberately ONE error: telling
	// "bad signature" apart from "bad base64" tells an attacker where they stand.
	ErrInvalidToken = fmt.Err("jwt", "token", "invalid")

	// ErrTokenExpired is separate because it is NOT an attack: the caller must be able
	// to tell "your session ended, log in again" from "this token is a forgery".
	ErrTokenExpired = fmt.Err("jwt", "token", "expired")

	// ErrEmptySecret is a refusal, not a failure. HMAC over an empty key is valid math:
	// it produces a token that verifies. A zero-value config would therefore mint
	// tokens that ANYONE can forge, and nothing would ever look wrong.
	ErrEmptySecret = fmt.Err("jwt", "secret", "empty")

	// ErrEmptySubject: a token that authenticates nobody is never what the caller meant.
	ErrEmptySubject = fmt.Err("jwt", "subject", "empty")
)

// DefaultTTL is the lifetime NewClaims uses when ttl <= 0.
const DefaultTTL = 86400 // 24h, in seconds

const (
	algHS256 = "HS256"
	typJWT   = "JWT"
)

type header struct {
	Alg string
	Typ string
}

func (h header) EncodeFields(w model.FieldWriter) {
	w.String("alg", h.Alg)
	w.String("typ", h.Typ)
}
func (h header) IsNil() bool { return false }

// Claims is the payload. Closed on purpose: the registered claims this ecosystem
// actually uses. No `map[string]any` bag — that is how JWT libraries grow holes.
type Claims struct {
	Sub string // subject: who the token authenticates
	Exp int64  // expiry, unix seconds
	Iat int64  // issued at, unix seconds
}

func (c Claims) EncodeFields(w model.FieldWriter) {
	w.String("sub", c.Sub)
	w.Int("exp", c.Exp)
	w.Int("iat", c.Iat)
}
func (c Claims) IsNil() bool { return false }
func (c *Claims) DecodeFields(r model.FieldReader) {
	c.Sub, _ = r.String("sub")
	c.Exp, _ = r.Int("exp")
	c.Iat, _ = r.Int("iat")
}

// NewClaims builds a claim set valid for ttl seconds from now.
func NewClaims(subject string, ttl int) Claims {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	n := now()
	return Claims{Sub: subject, Iat: n, Exp: n + int64(ttl)}
}

// Sign returns a signed HS256 token. It refuses to mint a forgeable or meaningless
// token rather than handing back one that merely looks fine.
func Sign(secret []byte, c Claims) (string, error) {
	if len(secret) == 0 {
		return "", ErrEmptySecret
	}
	if c.Sub == "" {
		return "", ErrEmptySubject
	}

	var h string
	if err := json.Encode(header{Alg: algHS256, Typ: typJWT}, &h); err != nil {
		return "", err
	}
	var p string
	if err := json.Encode(c, &p); err != nil {
		return "", err
	}

	signingInput := base64.URLEncode([]byte(h)) + "." + base64.URLEncode([]byte(p))
	return signingInput + "." + sign(secret, signingInput), nil
}

// Verify authenticates a token and returns its claims.
//
// The `alg` field of the header is READ BY NOBODY, and that is the point: this
// verifier always recomputes HS256. Choosing the algorithm from a value carried
// inside the untrusted token is the classic alg-confusion vulnerability — it is how
// `{"alg":"none"}` forgeries get accepted. Do not "fix" this by parsing the header.
func Verify(secret []byte, token string) (Claims, error) {
	var c Claims
	if len(secret) == 0 {
		return c, ErrEmptySecret
	}

	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrInvalidToken
	}

	expected := sign(secret, parts[0]+"."+parts[1])
	if !crypto.HMACEqual([]byte(parts[2]), []byte(expected)) {
		return c, ErrInvalidToken
	}

	// Only AFTER the signature is proven do we decode anything: never parse what you
	// have not authenticated.
	raw, err := base64.URLDecode(parts[1])
	if err != nil {
		return c, ErrInvalidToken
	}
	if err := json.Decode(string(raw), &c); err != nil {
		return c, ErrInvalidToken
	}

	// A token with no expiry is not "eternal", it is malformed: otherwise a payload
	// that simply omits `exp` would grant a session that never ends.
	if c.Exp <= 0 || c.Sub == "" {
		return Claims{}, ErrInvalidToken
	}
	if now() > c.Exp {
		return Claims{}, ErrTokenExpired
	}
	return c, nil
}

// sign is the ONE place the MAC is computed, so signing and verifying can never
// drift apart.
func sign(secret []byte, signingInput string) string {
	return base64.URLEncode(crypto.HMACSHA256(secret, []byte(signingInput)))
}

// now is unix seconds; tinywasm/time counts nanoseconds.
func now() int64 { return time.Now() / 1e9 }
