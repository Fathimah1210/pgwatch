package auth

import (
	"time"
)

// TokenValidator defines the interface for token validation
// This interface is compatible with both the original TokenManager
// and the new JWTTokenManager
type TokenValidator interface {
	// IsTokenValid checks if a token is valid and returns the instance name
	IsTokenValid(token string) (bool, string)
	
	// RecordUsage records that a token was used
	RecordUsage(token string)
	
	// AddToken adds a new token (implementation may vary)
	AddToken(token string, label string, expiresAt time.Time) error
	
	// RevokeToken revokes a token
	RevokeToken(token string) error
	
	// Close cleans up resources
	Close() error
}