package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Common errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token expired")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrTokenStorageFailed = errors.New("failed to store tokens")
)

// TokenInfo stores metadata about a token
type TokenInfo struct {
	Value      string    `json:"value"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	UsageCount int       `json:"usage_count"`
	Revoked    bool      `json:"revoked"`
}

// TokenManager manages authentication tokens
type TokenManager struct {
	tokens     map[string]TokenInfo
	mu         sync.RWMutex
	storagePath string
	autoSave   bool
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

// SetStoragePath sets the path for token persistence
func (tm *TokenManager) SetStoragePath(path string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.storagePath = path
}

// EnableAutoSave enables automatic saving of tokens when changes occur
func (tm *TokenManager) EnableAutoSave(enable bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.autoSave = enable
}

// SaveTokens saves tokens to a file
func (tm *TokenManager) SaveTokens() error {
	if tm.storagePath == "" {
		return nil // No storage path set
	}
	
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	// Ensure directory exists
	dir := filepath.Dir(tm.storagePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Join(ErrTokenStorageFailed, err)
	}
	
	// Marshal tokens to JSON
	data, err := json.MarshalIndent(tm.tokens, "", "  ")
	if err != nil {
		return errors.Join(ErrTokenStorageFailed, err)
	}
	
	// Write to file with secure permissions
	return os.WriteFile(tm.storagePath, data, 0600)
}

// LoadTokens loads tokens from a file
func (tm *TokenManager) LoadTokens() error {
	if tm.storagePath == "" {
		return nil // No storage path set
	}
	
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	// Check if file exists
	if _, err := os.Stat(tm.storagePath); os.IsNotExist(err) {
		return nil // File doesn't exist yet, that's okay
	}
	
	// Read file
	data, err := os.ReadFile(tm.storagePath)
	if err != nil {
		return errors.Join(ErrTokenStorageFailed, err)
	}
	
	// Unmarshal tokens
	return json.Unmarshal(data, &tm.tokens)
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
		
		if tm.autoSave {
			// Save in a goroutine to not block the caller
			go tm.SaveTokens()
		}
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
	
	if tm.autoSave {
		// Save in a goroutine to not block the caller
		go tm.SaveTokens()
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
		
		if tm.autoSave {
			// Save in a goroutine to not block the caller
			go tm.SaveTokens()
		}
		
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

// GetToken retrieves information about a specific token
func (tm *TokenManager) GetToken(token string) (TokenInfo, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	if info, exists := tm.tokens[token]; exists {
		return info, nil
	}
	
	return TokenInfo{}, ErrInvalidToken
}

// GenerateAndAddToken creates a new token, adds it to the manager, and returns it
func (tm *TokenManager) GenerateAndAddToken(label string, expiresInDays int) (string, error) {
	// Generate a secure token
	token, err := GenerateToken(32)
	if err != nil {
		return "", err
	}
	
	// Calculate expiration time if needed
	var expiresAt time.Time
	if expiresInDays > 0 {
		expiresAt = time.Now().AddDate(0, 0, expiresInDays)
	}
	
	// Add the token
	if err := tm.AddToken(token, label, expiresAt); err != nil {
		return "", err
	}
	
	return token, nil
}

// CleanupExpiredTokens removes expired tokens
func (tm *TokenManager) CleanupExpiredTokens() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	now := time.Now()
	count := 0
	
	for token, info := range tm.tokens {
		if !info.ExpiresAt.IsZero() && now.After(info.ExpiresAt) {
			delete(tm.tokens, token)
			count++
		}
	}
	
	if count > 0 && tm.autoSave {
		go tm.SaveTokens()
	}
	
	return count
}