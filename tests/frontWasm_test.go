//go:build wasm

package jwt_test

import "testing"

func TestJWT_WASM(t *testing.T) {
	RunJWTTests(t)
}
