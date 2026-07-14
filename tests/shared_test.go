package jwt_test

import (
	"testing"

	"github.com/tinywasm/base64"
	"github.com/tinywasm/crypto"
	"github.com/tinywasm/jwt"
)

// RunJWTTests is the single source of truth for both environments.
// Entry points: backStlib_test.go (!wasm) and frontWasm_test.go (wasm).
//
// A new test is added as a test_XxxYyy function REGISTERED HERE — never as a bare
// top-level TestXxx, or it runs in only one of the two environments.
func RunJWTTests(t *testing.T) {
	t.Run("RoundTrip", test_RoundTrip)
	t.Run("ZeroOutcomeIsForged", test_ZeroOutcomeIsForged)
	t.Run("ExpiredIsNotForged", test_ExpiredIsNotForged)
	t.Run("RejectsEmptySecret", test_RejectsEmptySecret)
	t.Run("RejectsEmptySubject", test_RejectsEmptySubject)
	t.Run("RejectsWrongSecret", test_RejectsWrongSecret)
	t.Run("RejectsTamperedPayload", test_RejectsTamperedPayload)
	t.Run("RejectsAlgNone", test_RejectsAlgNone)
	t.Run("RejectsMalformedShapes", test_RejectsMalformedShapes)
	t.Run("RejectsSplicedSignature", test_RejectsSplicedSignature)
	t.Run("RejectsMissingExp", test_RejectsMissingExp)
	t.Run("NoClaimsUnlessValid", test_NoClaimsUnlessValid)
}

var secret = []byte("a-256-bit-secret-for-the-test-abc")

func test_RoundTrip(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out != jwt.Valid {
		t.Fatalf("outcome: got %v, want valid", out)
	}
	if c.Sub != "u1" {
		t.Errorf("sub: got %q, want %q", c.Sub, "u1")
	}
	if c.Exp <= c.Iat {
		t.Errorf("exp (%d) must be after iat (%d)", c.Exp, c.Iat)
	}
}

// Closed by default: the zero value of Outcome must be the DENY verdict. If someone
// later reorders the enum so that `Valid` lands on zero, every `var out jwt.Outcome`
// and every unset field silently becomes "authentic".
func test_ZeroOutcomeIsForged(t *testing.T) {
	var zero jwt.Outcome
	if zero != jwt.Forged {
		t.Fatalf("the zero value of Outcome is %v, not Forged: an unset verdict now means authentic", zero)
	}
}

// THE regression this type exists for.
//
// With `(Claims, error)`, tinywasm/user wrote `if err != nil { EventJWTTampered }` and
// so reported every routine expiry as a forgery — firing the loudest alarm in the
// system on its quietest event, and burying real attacks in the noise. Expiry and
// forgery must be different VALUES, not two sentinels sharing an error channel.
func test_ExpiredIsNotForged(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: 1, Exp: 2}) // long past
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatalf("an expired token is not a caller error: got %v", err)
	}
	if out != jwt.Expired {
		t.Fatalf("outcome: got %v, want expired", out)
	}
	if out == jwt.Forged {
		t.Error("an expired session was classified as a forgery")
	}
}

// Nothing but Valid may hand back usable claims: an expired or forged token authorizes
// nobody, and returning its subject invites a caller to use it anyway.
func test_NoClaimsUnlessValid(t *testing.T) {
	expired, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: 1, Exp: 2})
	if err != nil {
		t.Fatal(err)
	}
	forged := "a.b.c"

	for _, tok := range []string{expired, forged} {
		c, out, err := jwt.Verify(secret, tok)
		if err != nil {
			t.Fatal(err)
		}
		if out == jwt.Valid {
			t.Fatalf("token %q was accepted", tok)
		}
		if c.Sub != "" || c.Exp != 0 {
			t.Errorf("outcome %v leaked claims: %+v", out, c)
		}
	}
}

// HMAC over an empty key is valid math: it yields a token that verifies. If Sign
// accepted it, a zero-value config would mint tokens ANYONE can forge, and nothing
// would look wrong. An empty secret is a CALLER bug, so it travels as an error — not
// as a verdict on the token.
func test_RejectsEmptySecret(t *testing.T) {
	if _, err := jwt.Sign(nil, jwt.NewClaims("u1", 3600)); err != jwt.ErrEmptySecret {
		t.Errorf("Sign with empty secret: got %v, want ErrEmptySecret", err)
	}
	_, out, err := jwt.Verify(nil, "a.b.c")
	if err != jwt.ErrEmptySecret {
		t.Errorf("Verify with empty secret: got %v, want ErrEmptySecret", err)
	}
	if out != jwt.Forged {
		t.Errorf("a caller error must still deny: got %v", out)
	}
}

// A token that authenticates nobody would let "" through as an identity, and "" is the
// anonymous user across this ecosystem.
func test_RejectsEmptySubject(t *testing.T) {
	if _, err := jwt.Sign(secret, jwt.Claims{Exp: 1 << 40}); err != jwt.ErrEmptySubject {
		t.Errorf("got %v, want ErrEmptySubject", err)
	}
}

func test_RejectsWrongSecret(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := jwt.Verify([]byte("another-secret-entirely-000000000"), tok); out != jwt.Forged {
		t.Errorf("got %v, want forged", out)
	}
}

// The signature covers header+payload: swapping in a different subject must not survive.
func test_RejectsTamperedPayload(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	parts := split3(t, tok)
	forged := parts[0] + "." +
		base64.URLEncode([]byte(`{"sub":"admin","exp":99999999999,"iat":1}`)) + "." +
		parts[2]

	if _, out, _ := jwt.Verify(secret, forged); out != jwt.Forged {
		t.Errorf("a payload swap was accepted: got %v", out)
	}
}

// THE canonical JWT vulnerability: a token declaring {"alg":"none"} with an empty
// signature. Verify must always recompute HS256 and never consult the header's alg.
func test_RejectsAlgNone(t *testing.T) {
	h := base64.URLEncode([]byte(`{"alg":"none","typ":"JWT"}`))
	p := base64.URLEncode([]byte(`{"sub":"admin","exp":99999999999,"iat":1}`))

	for _, tok := range []string{
		h + "." + p + ".",   // empty signature
		h + "." + p + ".AA", // junk signature
	} {
		if _, out, _ := jwt.Verify(secret, tok); out != jwt.Forged {
			t.Errorf("alg=none forgery ACCEPTED (%v): %q", out, tok)
		}
	}
}

func test_RejectsMalformedShapes(t *testing.T) {
	for _, tok := range []string{"", "a", "a.b", "a.b.c.d", "..", "a.b.c"} {
		if _, out, _ := jwt.Verify(secret, tok); out != jwt.Forged {
			t.Errorf("malformed token ACCEPTED (%v): %q", out, tok)
		}
	}
}

// A signature is valid only for ITS OWN header+payload: pasting a valid signature from
// another token must not authenticate this one.
func test_RejectsSplicedSignature(t *testing.T) {
	a, err := jwt.Sign(secret, jwt.NewClaims("alice", 3600))
	if err != nil {
		t.Fatal(err)
	}
	b, err := jwt.Sign(secret, jwt.NewClaims("bob", 3600))
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := split3(t, a), split3(t, b)

	spliced := pa[0] + "." + pa[1] + "." + pb[2] // alice's claims, bob's signature
	if _, out, _ := jwt.Verify(secret, spliced); out != jwt.Forged {
		t.Errorf("spliced signature accepted: got %v", out)
	}
}

// A correctly signed payload that simply omits `exp` must not grant an eternal session.
func test_RejectsMissingExp(t *testing.T) {
	h := base64.URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	noExp := base64.URLEncode([]byte(`{"sub":"u1","iat":1}`))

	if _, out, _ := jwt.Verify(secret, resign(h, noExp)); out != jwt.Forged {
		t.Errorf("token without exp accepted (eternal session): got %v", out)
	}
}

// resign produces a VALIDLY signed token for an arbitrary header/payload pair.
//
// The MAC is recomputed HERE, in the test, rather than through a "sign anything" helper
// on the public API: exporting one would hand consumers the very footgun this library
// exists to close (a caller-chosen header is how alg-confusion starts). A test is
// allowed to forge; the API is not allowed to make forging easy.
func resign(header, payload string) string {
	signingInput := header + "." + payload
	return signingInput + "." + base64.URLEncode(crypto.HMACSHA256(secret, []byte(signingInput)))
}

func split3(t *testing.T, token string) [3]string {
	t.Helper()
	var out [3]string
	start, n := 0, 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if n > 2 {
				t.Fatalf("too many parts in %q", token)
			}
			out[n] = token[start:i]
			n++
			start = i + 1
		}
	}
	if n != 2 {
		t.Fatalf("expected 3 parts, got %d in %q", n+1, token)
	}
	out[2] = token[start:]
	return out
}
