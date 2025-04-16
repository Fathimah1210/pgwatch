package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// TokenManager manages authentication tokens
type TokenManager struct {
	tokens map[string]TokenInfo
	mu     sync.RWMutex
}

var (
	defaultManager *TokenManager
	managerOnce    sync.Once
)

// InitTokenManager initializes the token manager with initial tokens
func InitTokenManager(initialTokens map[string]bool) *TokenManager {
	managerOnce.Do(func() {
		defaultManager = &TokenManager{
			tokens: make(map[string]TokenInfo),
		}
		
		// Add initial tokens
		now := time.Now()
		for token, enabled := range initialTokens {
			if enabled {
				defaultManager.tokens[token] = TokenInfo{
					Value:      token,
					Label:      "Initial token",
					CreatedAt:  now,
					ExpiresAt:  time.Time{}, // No expiration
					LastUsedAt: time.Time{},
					UsageCount: 0,
					Revoked:    false,
				}
			}
		}
	})
	return defaultManager
}

// GetTokenManager returns the token manager instance
func GetTokenManager() *TokenManager {
	if defaultManager == nil {
		return InitTokenManager(nil)
	}
	return defaultManager
}

// GenerateToken creates a cryptographically secure token
func GenerateToken(length int) (string, error) {
	if length < 16 {
		length = 16 // Ensure minimum security
	}
	
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashToken creates a secure hash of a token
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// IsTokenValid checks if a token is valid
func (tm *TokenManager) IsTokenValid(token string) bool {
	if token == "" {
		return false
	}
	
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	info, exists := tm.tokens[token]
	if !exists || info.Revoked {
		return false
	}
	
	// Check expiration
	if !info.ExpiresAt.IsZero() && time.Now().After(info.ExpiresAt) {
		return false
	}
	
	return true
}

// RecordUsage updates usage statistics for a token
func (tm *TokenManager) RecordUsage(token string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if info, exists := tm.tokens[token]; exists {
		info.LastUsedAt = time.Now()
		info.UsageCount++
		tm.tokens[token] = info
	}
}

// AddToken adds a new token
func (tm *TokenManager) AddToken(token, label string, expiresAt time.Time) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tm.tokens[token] = TokenInfo{
		Value:      token,
		Label:      label,
		CreatedAt:  time.Now(),
		ExpiresAt:  expiresAt,
		LastUsedAt: time.Time{},
		UsageCount: 0,
		Revoked:    false,
	}
	
	return nil
}

// RevokeToken revokes a token
func (tm *TokenManager) RevokeToken(token string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if info, exists := tm.tokens[token]; exists {
		info.Revoked = true
		tm.tokens[token] = info
		return nil
	}
	
	return ErrInvalidToken
}

// ListTokens returns a list of all tokens
func (tm *TokenManager) ListTokens() []TokenInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	result := make([]TokenInfo, 0, len(tm.tokens))
	for _, info := range tm.tokens {
		// Return a copy to prevent modification
		result = append(result, info)
	}
	
	return result
}