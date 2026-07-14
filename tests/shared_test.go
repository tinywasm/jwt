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
	t.Run("RejectsEmptySecret", test_RejectsEmptySecret)
	t.Run("RejectsEmptySubject", test_RejectsEmptySubject)
	t.Run("RejectsWrongSecret", test_RejectsWrongSecret)
	t.Run("RejectsTamperedPayload", test_RejectsTamperedPayload)
	t.Run("RejectsAlgNone", test_RejectsAlgNone)
	t.Run("RejectsMalformedShapes", test_RejectsMalformedShapes)
	t.Run("RejectsSplicedSignature", test_RejectsSplicedSignature)
	t.Run("ExpiredIsDistinguishable", test_ExpiredIsDistinguishable)
	t.Run("RejectsMissingExp", test_RejectsMissingExp)
}

var secret = []byte("a-256-bit-secret-for-the-test-abc")

func test_RoundTrip(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "u1" {
		t.Errorf("sub: got %q, want %q", c.Sub, "u1")
	}
	if c.Exp <= c.Iat {
		t.Errorf("exp (%d) must be after iat (%d)", c.Exp, c.Iat)
	}
}

// HMAC over an empty key is valid math: it yields a token that verifies. If Sign
// accepted it, a zero-value config would mint tokens ANYONE can forge, and nothing
// would look wrong. Both directions must refuse.
func test_RejectsEmptySecret(t *testing.T) {
	if _, err := jwt.Sign(nil, jwt.NewClaims("u1", 3600)); err != jwt.ErrEmptySecret {
		t.Errorf("Sign with empty secret: got %v, want ErrEmptySecret", err)
	}
	if _, err := jwt.Verify(nil, "a.b.c"); err != jwt.ErrEmptySecret {
		t.Errorf("Verify with empty secret: got %v, want ErrEmptySecret", err)
	}
}

// A token that authenticates nobody would let "" through as an identity.
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
	if _, err := jwt.Verify([]byte("another-secret-entirely-000000000"), tok); err != jwt.ErrInvalidToken {
		t.Errorf("got %v, want ErrInvalidToken", err)
	}
}

// Re-encoding the payload with a different subject must not survive: the signature
// covers header+payload.
func test_RejectsTamperedPayload(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	parts := split3(t, tok)
	forged := parts[0] + "." +
		base64.URLEncode([]byte(`{"sub":"admin","exp":99999999999,"iat":1}`)) + "." +
		parts[2]

	if _, err := jwt.Verify(secret, forged); err != jwt.ErrInvalidToken {
		t.Errorf("a re-signed-nothing payload swap was accepted: got %v", err)
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
		if _, err := jwt.Verify(secret, tok); err == nil {
			t.Errorf("alg=none forgery ACCEPTED: %q", tok)
		}
	}
}

func test_RejectsMalformedShapes(t *testing.T) {
	for _, tok := range []string{
		"",
		"a",
		"a.b",
		"a.b.c.d",
		"..",
		"a.b.c",
	} {
		if _, err := jwt.Verify(secret, tok); err == nil {
			t.Errorf("malformed token ACCEPTED: %q", tok)
		}
	}
}

// A signature is only valid for ITS OWN header+payload: pasting a valid signature
// from another token must not authenticate this one.
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
	if _, err := jwt.Verify(secret, spliced); err != jwt.ErrInvalidToken {
		t.Errorf("spliced signature accepted: got %v", err)
	}
}

// Expiry is NOT an attack: the caller must tell "log in again" from "this is a
// forgery", so the errors must differ.
func test_ExpiredIsDistinguishable(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: 1, Exp: 2}) // long past
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwt.Verify(secret, tok)
	if err != jwt.ErrTokenExpired {
		t.Fatalf("got %v, want ErrTokenExpired", err)
	}
	if err == jwt.ErrInvalidToken {
		t.Error("expired must not collapse into ErrInvalidToken")
	}
}

// A correctly signed payload that simply omits `exp` must not grant an eternal
// session.
func test_RejectsMissingExp(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: 1, Exp: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	parts := split3(t, tok)

	// Re-sign a payload WITHOUT exp, so the signature is genuinely valid: the only
	// thing that can reject it is the claim check itself.
	noExp := base64.URLEncode([]byte(`{"sub":"u1","iat":1}`))
	forged, err := resign(parts[0], noExp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwt.Verify(secret, forged); err != jwt.ErrInvalidToken {
		t.Errorf("token without exp accepted (eternal session): got %v", err)
	}
}

// resign produces a VALIDLY signed token for an arbitrary header/payload pair.
//
// The MAC is recomputed HERE, in the test, rather than through a "sign anything"
// helper on the public API: exporting one would hand consumers the very footgun this
// library exists to close (a caller-chosen header is how alg-confusion starts). A test
// is allowed to forge; the API is not allowed to make forging easy.
func resign(header, payload string) (string, error) {
	signingInput := header + "." + payload
	sig := base64.URLEncode(crypto.HMACSHA256(secret, []byte(signingInput)))
	return signingInput + "." + sig, nil
}

func split3(t *testing.T, token string) [3]string {
	t.Helper()
	var out [3]string
	i, start, n := 0, 0, 0
	for ; i < len(token); i++ {
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
