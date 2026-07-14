//go:build !wasm

package jwt_test

import "testing"

func TestJWT_Native(t *testing.T) {
	RunJWTTests(t)
}
