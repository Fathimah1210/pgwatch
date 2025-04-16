package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInitTokenManager(t *testing.T) {
	// Reset the singleton for testing
	defaultManager = nil
	managerOnce = sync.Once{}

	t.Run("Initialize with tokens", func(t *testing.T) {
		initialTokens := map[string]bool{
			"test_token1": true,
			"test_token2": true,
		}
		
		tm := InitTokenManager(initialTokens)
		assert.NotNil(t, tm)
		
		// Verify both tokens are recognized as valid
		assert.True(t, tm.IsTokenValid("test_token1"))
		assert.True(t, tm.IsTokenValid("test_token2"))
		assert.False(t, tm.IsTokenValid("invalid_token"))
	})
	
	t.Run("Initialize with empty tokens", func(t *testing.T) {
		// Reset for this test
		defaultManager = nil
		managerOnce = sync.Once{}
		
		tm := InitTokenManager(nil)
		assert.NotNil(t, tm)
		
		// No tokens should be valid
		assert.False(t, tm.IsTokenValid("any_token"))
	})
	
	t.Run("Singleton behavior", func(t *testing.T) {
		// Reset for this test
		defaultManager = nil
		managerOnce = sync.Once{}
		
		tm1 := InitTokenManager(map[string]bool{"first_init": true})
		tm2 := InitTokenManager(map[string]bool{"second_init": true}) // Should be ignored
		
		assert.Same(t, tm1, tm2, "Should return the same instance")
		assert.True(t, tm1.IsTokenValid("first_init"))
		assert.False(t, tm1.IsTokenValid("second_init"), "Second initialization should be ignored")
		
		// GetTokenManager should return the same instance
		tm3 := GetTokenManager()
		assert.Same(t, tm1, tm3)
	})
}

func TestTokenManagerOperations(t *testing.T) {
	// Reset the singleton for testing
	defaultManager = nil
	managerOnce = sync.Once{}
	
	tm := InitTokenManager(map[string]bool{"initial_token": true})
	
	t.Run("Add token", func(t *testing.T) {
		err := tm.AddToken("new_token", "Test Token", time.Time{})
		assert.NoError(t, err)
		assert.True(t, tm.IsTokenValid("new_token"))
	})
	
	t.Run("Add token with expiration", func(t *testing.T) {
		expiredTime := time.Now().Add(-1 * time.Hour) // 1 hour in the past
		err := tm.AddToken("expired_token", "Expired Token", expiredTime)
		assert.NoError(t, err)
		
		// Expired token should not be valid
		assert.False(t, tm.IsTokenValid("expired_token"))
		
		// Add a token expiring in the future
		futureTime := time.Now().Add(1 * time.Hour) // 1 hour in the future
		err = tm.AddToken("future_token", "Future Token", futureTime)
		assert.NoError(t, err)
		
		// Future token should be valid
		assert.True(t, tm.IsTokenValid("future_token"))
	})
	
	t.Run("Revoke token", func(t *testing.T) {
		// Add a token first
		err := tm.AddToken("revoke_test", "Revoke Test", time.Time{})
		assert.NoError(t, err)
		assert.True(t, tm.IsTokenValid("revoke_test"))
		
		// Now revoke it
		err = tm.RevokeToken("revoke_test")
		assert.NoError(t, err)
		assert.False(t, tm.IsTokenValid("revoke_test"))
		
		// Trying to revoke non-existent token should return error
		err = tm.RevokeToken("non_existent")
		assert.Error(t, err)
	})
	
	t.Run("Token usage tracking", func(t *testing.T) {
		// Add a token
		err := tm.AddToken("usage_token", "Usage Tracking Test", time.Time{})
		assert.NoError(t, err)
		
		// Initial state
		tokens := tm.ListTokens()
		var tokenInfo TokenInfo
		for _, info := range tokens {
			if info.Value == "usage_token" {
				tokenInfo = info
				break
			}
		}
		
		assert.Equal(t, "usage_token", tokenInfo.Value)
		assert.Equal(t, 0, tokenInfo.UsageCount)
		assert.True(t, tokenInfo.LastUsedAt.IsZero())
		
		// Record usage
		tm.RecordUsage("usage_token")
		
		// Check updated state
		tokens = tm.ListTokens()
		for _, info := range tokens {
			if info.Value == "usage_token" {
				tokenInfo = info
				break
			}
		}
		
		assert.Equal(t, 1, tokenInfo.UsageCount)
		assert.False(t, tokenInfo.LastUsedAt.IsZero(), "LastUsedAt should be updated")
	})
	
	t.Run("List tokens", func(t *testing.T) {
		// Clear previous tokens and add new ones
		defaultManager = nil
		managerOnce = sync.Once{}
		
		tm := InitTokenManager(map[string]bool{
			"token1": true,
			"token2": true,
		})
		
		tokens := tm.ListTokens()
		assert.Len(t, tokens, 2)
		
		// Map tokens by value for easier checking
		tokenMap := make(map[string]TokenInfo)
		for _, token := range tokens {
			tokenMap[token.Value] = token
		}
		
		assert.Contains(t, tokenMap, "token1")
		assert.Contains(t, tokenMap, "token2")
	})
}

func TestTokenGenerationAndHashing(t *testing.T) {
	t.Run("Generate token", func(t *testing.T) {
		token1, err := GenerateToken(32)
		assert.NoError(t, err)
		assert.NotEmpty(t, token1)
		
		token2, err := GenerateToken(32)
		assert.NoError(t, err)
		assert.NotEmpty(t, token2)
		
		// Two generated tokens should be different
		assert.NotEqual(t, token1, token2)
	})
	
	t.Run("Generate short token", func(t *testing.T) {
		// Even if requested length is too short, it should enforce minimum security
		token, err := GenerateToken(4)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		
		// Should be longer than requested due to minimum length enforcement
		decoded, err := base64.URLEncoding.DecodeString(token)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(decoded), 16, "Token should enforce minimum length")
	})
	
	t.Run("Hash token", func(t *testing.T) {
		hash1 := HashToken("test_token")
		hash2 := HashToken("test_token")
		hash3 := HashToken("different_token")
		
		// Same token should produce same hash
		assert.Equal(t, hash1, hash2)
		
		// Different tokens should produce different hashes
		assert.NotEqual(t, hash1, hash3)
		
		// Hash should be fixed length (SHA-256 hex = 64 chars)
		assert.Len(t, hash1, 64)
	})
}

func TestTokenManagerEdgeCases(t *testing.T) {
	// Reset the singleton for testing
	defaultManager = nil
	managerOnce = sync.Once{}
	
	tm := InitTokenManager(nil)
	
	t.Run("Empty token", func(t *testing.T) {
		assert.False(t, tm.IsTokenValid(""))
	})
	
	t.Run("Record usage for non-existent token", func(t *testing.T) {
		// Should not panic
		tm.RecordUsage("non_existent")
	})
	
	t.Run("GetTokenManager without init", func(t *testing.T) {
		// Reset the singleton
		defaultManager = nil
		managerOnce = sync.Once{}
		
		// Should initialize a new instance
		tm := GetTokenManager()
		assert.NotNil(t, tm)
	})
}