package auth

import (
	"errors"
	"time"
)

// Common errors
var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrExpiredToken   = errors.New("token expired")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// TokenInfo stores metadata about a token
type TokenInfo struct {
	Value      string    // Token value (or hash depending on implementation)
	Label      string    // Human-readable label for the token
	CreatedAt  time.Time // When the token was created
	ExpiresAt  time.Time // When the token expires (zero time means no expiration)
	LastUsedAt time.Time // When the token was last used
	UsageCount int       // How many times the token has been used
	Revoked    bool      // Whether the token has been revoked
}

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	// IsTokenValid checks if a token is valid
	IsTokenValid(token string) bool
	
	// RecordUsage records that a token was used
	RecordUsage(token string)
	
	// AddToken adds a new token
	AddToken(token string, label string, expiresAt time.Time) error
	
	// RevokeToken revokes a token
	RevokeToken(token string) error
}