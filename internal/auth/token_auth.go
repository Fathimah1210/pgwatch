package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Token represents a single token with metadata
type Token struct {
	Value     string
	ExpiresAt time.Time
	LastUsed  time.Time
	UsageCount int
}

// TokenManager manages all tokens in a thread-safe way
type TokenManager struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

var (
	manager     *TokenManager
	managerOnce sync.Once
)

// Config contains token manager configuration
type Config struct {
	RateLimitCount  int           // Max requests per duration
	RateLimitWindow time.Duration // e.g., 1 * time.Minute
}

// InitTokenManager initializes the token manager (thread-safe singleton)
func InitTokenManager(initialTokens map[string]bool, config ...Config) *TokenManager {
	managerOnce.Do(func() {
		tokens := make(map[string]*Token)
		now := time.Now()
		
		for tokenStr := range initialTokens {
			tokens[tokenStr] = &Token{
				Value:    tokenStr,
				// Default expiration: 30 days
				ExpiresAt: now.Add(30 * 24 * time.Hour),
			}
		}

		manager = &TokenManager{
			tokens: tokens,
		}
	})
	return manager
}

// GenerateSecureToken creates a cryptographically secure token
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// AddToken adds a new token with optional expiration
func (tm *TokenManager) AddToken(token string, expiresIn ...time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	expiry := time.Now().Add(30 * 24 * time.Hour) // Default 30 days
	if len(expiresIn) > 0 {
		expiry = time.Now().Add(expiresIn[0])
	}

	tm.tokens[token] = &Token{
		Value:     token,
		ExpiresAt: expiry,
	}
}

// IsTokenValid checks token validity (constant-time + expiry + rate limit)
func (tm *TokenManager) IsTokenValid(token string) (bool, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Constant-time search
	var validToken *Token
	for _, t := range tm.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(t.Value)) == 1 {
			validToken = t
			break
		}
	}

	if validToken == nil {
		return false, errors.New("invalid token")
	}

	// Check expiration
	if time.Now().After(validToken.ExpiresAt) {
		return false, errors.New("token expired")
	}

	// Check rate limit (example: 100 requests/minute)
	if validToken.UsageCount > 100 && time.Since(validToken.LastUsed) < time.Minute {
		return false, errors.New("rate limit exceeded")
	}

	return true, nil
}

// RecordUsage updates token usage metrics
func (tm *TokenManager) RecordUsage(token string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if t, exists := tm.tokens[token]; exists {
		t.LastUsed = time.Now()
		t.UsageCount++
	}
}

// RevokeToken removes a token immediately
func (tm *TokenManager) RevokeToken(token string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.tokens, token)
}

// GetTokenManager returns the singleton instance
func GetTokenManager() *TokenManager {
	return manager
}