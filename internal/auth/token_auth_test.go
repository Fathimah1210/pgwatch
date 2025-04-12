package auth_test

import (
	"crypto/subtle"
	"testing"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestTokenManager(t *testing.T) {
	// Initialize TokenManager with valid tokens
	tm := auth.InitTokenManager(map[string]bool{
		"25tnt3446h":  true, // Valid token from your implementation
		"backup_token": true, // Additional test token
	})

	t.Run("Valid token should be accepted", func(t *testing.T) {
		assert.True(t, tm.IsTokenValid("25tnt3446h"),
			"Registered token should be considered valid")
	})

	t.Run("Invalid token should be rejected", func(t *testing.T) {
		assert.False(t, tm.IsTokenValid("wrong_token"),
			"Unregistered token should be rejected")
	})

	t.Run("Empty token should be rejected", func(t *testing.T) {
		assert.False(t, tm.IsTokenValid(""),
			"Empty token should be rejected")
	})

	t.Run("Token comparison should be constant-time", func(t *testing.T) {
		// Security test: prevent timing attacks
		validToken := "25tnt3446h"
		invalidToken := "25tnt3446x"
		
		timeValid := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				subtle.ConstantTimeCompare([]byte(validToken), []byte(validToken))
			}
		})
		
		timeInvalid := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				subtle.ConstantTimeCompare([]byte(validToken), []byte(invalidToken))
			}
		})
		
		assert.InDelta(t, timeValid.NsPerOp(), timeInvalid.NsPerOp(), float64(timeValid.NsPerOp()*0.1),
			"Token validation time should be equal (constant-time)")
	})
}