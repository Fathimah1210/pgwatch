package auth

import (
	"context"
	"errors"
	"time"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
	"github.com/cybertec-postgresql/pgwatch/v3/internal/rpc/models"
)

// ReceiverInterface defines the interface that RPC receivers must implement
type ReceiverInterface interface {
	UpdateMeasurements(data interface{}, reply *string) error
	SyncMetric(data interface{}, reply *string) error
}

// AuthenticatedWrapper wraps an RPC receiver with authentication
type AuthenticatedWrapper struct {
	receiver      ReceiverInterface
	tokenManager  *auth.TokenManager
	auditLogger   *auth.AuditLogger
	timeout       time.Duration
	insecureMode  bool
}

// NewAuthenticatedWrapper creates a new authenticated wrapper
func NewAuthenticatedWrapper(receiver ReceiverInterface, token string, insecureMode bool) *AuthenticatedWrapper {
	// Initialize token manager if needed
	tokenManager := auth.GetTokenManager()
	if token != "" {
		tokenManager.AddToken(token, "Initial token", time.Time{})
	}
	
	return &AuthenticatedWrapper{
		receiver:     receiver,
		tokenManager: tokenManager,
		auditLogger:  auth.GetAuditLogger(),
		timeout:      5 * time.Second,
		insecureMode: insecureMode,
	}
}

// UpdateMeasurements handles measurement updates with authentication
func (aw *AuthenticatedWrapper) UpdateMeasurements(req *models.AuthRequest, reply *string) error {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), aw.timeout)
	defer cancel()
	
	// Skip authentication in insecure mode
	if !aw.insecureMode {
		if !aw.tokenManager.IsTokenValid(req.Token) {
			aw.auditLogger.LogAuthAttempt(req.Token, "unknown", false, "Invalid token")
			return errors.New("authentication failed")
		}
		
		// Record token usage
		aw.tokenManager.RecordUsage(req.Token)
		aw.auditLogger.LogAuthAttempt(req.Token, "unknown", true, "Measurement update")
	}
	
	// Process the request
	resultChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		resultChan <- aw.receiver.UpdateMeasurements(req.Data, reply)
	}()
	
	// Wait for response or timeout
	select {
	case err := <-resultChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SyncMetric handles metric synchronization with authentication
func (aw *AuthenticatedWrapper) SyncMetric(req *models.AuthRequest, reply *string) error {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), aw.timeout)
	defer cancel()
	
	// Skip authentication in insecure mode
	if !aw.insecureMode {
		if !aw.tokenManager.IsTokenValid(req.Token) {
			aw.auditLogger.LogAuthAttempt(req.Token, "unknown", false, "Invalid token")
			return errors.New("authentication failed")
		}
		
		// Record token usage
		aw.tokenManager.RecordUsage(req.Token)
		aw.auditLogger.LogAuthAttempt(req.Token, "unknown", true, "Sync metric")
	}
	
	// Process the request
	resultChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		resultChan <- aw.receiver.SyncMetric(req.Data, reply)
	}()
	
	// Wait for response or timeout
	select {
	case err := <-resultChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// VerifyToken provides a simple way to check token validity
func (aw *AuthenticatedWrapper) VerifyToken(token string, valid *bool) error {
	*valid = aw.tokenManager.IsTokenValid(token)
	return nil
}