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

// Outcome is the CLOSED set of verdicts on a token. It is not an error: a token being
// expired or forged is this function working correctly, and the caller must act
// differently on each — "log in again" is not "you are under attack".
//
// It is an enum rather than a sentinel error on purpose. With `(Claims, error)` a
// caller can write `if err != nil { alarm() }` and collapse a routine expiry into a
// forgery alarm — which is exactly what happened in tinywasm/user, drowning real
// tampering in noise. A closed type makes that collapse something you have to
// deliberately write, not something you get by forgetting.
type Outcome uint8

const (
	// Forged is the ZERO VALUE: closed by default. Anything not proven authentic —
	// wrong shape, bad signature, undecodable payload, missing claims — is this.
	// The verdict does not say WHICH: telling "bad signature" apart from "bad base64"
	// tells an attacker where they stand.
	Forged Outcome = iota

	// Valid: authentic and in date. The Claims returned alongside are trustworthy.
	Valid

	// Expired: authentic, but past its `exp`. NOT an attack — the session simply ended.
	Expired
)

func (o Outcome) String() string {
	switch o {
	case Valid:
		return "valid"
	case Expired:
		return "expired"
	default:
		return "forged"
	}
}

var (
	// ErrEmptySecret is a refusal, not a failure. HMAC over an empty key is valid math:
	// it produces a token that verifies. A zero-value config would therefore mint
	// tokens that ANYONE can forge, and nothing would ever look wrong.
	//
	// It is an `error`, not an Outcome, because it means THE CALLER is broken — not the
	// token. The two must never share a channel.
	ErrEmptySecret = fmt.Err("jwt", "secret", "empty")

	// ErrEmptySubject: a token that authenticates nobody is never what the caller meant.
	ErrEmptySubject = fmt.Err("jwt", "subject", "empty")
)

// DefaultTTL is the lifetime NewClaims uses when ttl <= 0.
const DefaultTTL = 86400 // 24h, in seconds

// Leeway is the clock skew tolerated when checking exp.
// It is a constant rather than a parameter because the zero value (no leeway)
// would cause intermittent 401s in distributed systems due to clock drift.
const Leeway = 60

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

// Verify authenticates a token and returns its verdict.
//
// The two return channels mean different things, and that separation IS the API:
//
//	error   — THE CALLER is broken (an empty secret). A configuration bug.
//	Outcome — what the TOKEN is: Valid, Expired, or Forged. Never an error.
//
// Claims are meaningful only when the Outcome is Valid; otherwise they are zero.
//
// The `alg` field of the header is READ BY NOBODY, and that is the point: this
// verifier always recomputes HS256. Choosing the algorithm from a value carried
// inside the untrusted token is the classic alg-confusion vulnerability — it is how
// `{"alg":"none"}` forgeries get accepted. Do not "fix" this by parsing the header.
func Verify(secret []byte, token string) (Claims, Outcome, error) {
	if len(secret) == 0 {
		return Claims{}, Forged, ErrEmptySecret
	}

	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, Forged, nil
	}

	expected := sign(secret, parts[0]+"."+parts[1])
	if !crypto.HMACEqual([]byte(parts[2]), []byte(expected)) {
		return Claims{}, Forged, nil
	}

	return verifyWithPayload(parts[1])
}

// VerifyAny tries each secret and returns the verdict of the first that authenticates
// the token. For rotation: pass the new secret first, the old one second.
//
// It ensures constant-time traversal of all secrets to avoid leaking which one
// matched through timing.
func VerifyAny(secrets [][]byte, token string) (Claims, Outcome, error) {
	if len(secrets) == 0 {
		return Claims{}, Forged, ErrEmptySecret
	}

	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, Forged, nil
	}

	signingInput := parts[0] + "." + parts[1]
	sig := []byte(parts[2])

	var bestClaims Claims
	var bestOutcome Outcome

	found := false
	for _, s := range secrets {
		if len(s) == 0 {
			return Claims{}, Forged, ErrEmptySecret
		}

		expected := sign(s, signingInput)
		if crypto.HMACEqual(sig, []byte(expected)) {
			// Signature matches. Now we need to know if it's Valid or Expired.
			// We only care about the result if it's the first match we found.
			// But we MUST continue the loop to keep constant time.
			if !found {
				c, out, _ := verifyWithPayload(parts[1])
				bestClaims = c
				bestOutcome = out
				found = true
			}
		}
	}

	if !found {
		return Claims{}, Forged, nil
	}
	return bestClaims, bestOutcome, nil
}

// verifyWithPayload is a helper for Verify and VerifyAny that decodes and checks
// expiry once the signature is already proven.
func verifyWithPayload(payloadB64 string) (Claims, Outcome, error) {
	raw, err := base64.URLDecode(payloadB64)
	if err != nil {
		return Claims{}, Forged, nil
	}
	var c Claims
	if err := json.Decode(string(raw), &c); err != nil {
		return Claims{}, Forged, nil
	}

	if c.Exp <= 0 || c.Sub == "" {
		return Claims{}, Forged, nil
	}
	if now() > c.Exp+Leeway {
		return Claims{}, Expired, nil
	}
	return c, Valid, nil
}

// FromBearer extracts the token from an Authorization header value.
// A missing or non-Bearer header yields ok == false; the token is never guessed.
// Case-insensitive for the "Bearer " scheme.
func FromBearer(authorizationHeader string) (token string, ok bool) {
	const bearer = "bearer "
	if len(authorizationHeader) <= len(bearer) {
		return "", false
	}
	low := fmt.ToLower(authorizationHeader[:len(bearer)])
	if low != bearer {
		return "", false
	}
	return authorizationHeader[len(bearer):], true
}

// DecodeUnverified reads the claims WITHOUT checking the signature. The token is
// UNTRUSTED input: treat the result as a display hint, never as an authorization
// decision.
//
// It follows the same shape requirements as Verify (3 parts, base64 valid, sub and exp
// present).
func DecodeUnverified(token string) (Claims, error) {
	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Err("jwt", "decode", "malformed")
	}

	raw, err := base64.URLDecode(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Decode(string(raw), &c); err != nil {
		return Claims{}, err
	}

	if c.Exp <= 0 || c.Sub == "" {
		return Claims{}, fmt.Err("jwt", "decode", "missing-claims")
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
