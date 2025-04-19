package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

var (
	// JWT-specific errors
	ErrJWTInvalidSignature = errors.New("invalid JWT signature")
	ErrJWTMissingClaim     = errors.New("missing required JWT claim")
	ErrJWTExpired          = errors.New("JWT token expired")
	ErrJWTRevoked          = errors.New("JWT token has been revoked")
	ErrJWTDatabaseError    = errors.New("JWT database error")
)

// JWTTokenManager manages authentication tokens with JWT and PostgreSQL
type JWTTokenManager struct {
	db        *sql.DB
	jwtSecret []byte
	mu        sync.RWMutex
}

// TokenClaims contains the JWT claims for pgwatch tokens
type TokenClaims struct {
	jwt.StandardClaims
	InstanceName string `json:"instance_name"`
	Label        string `json:"label,omitempty"`
}

// JWTTokenInfo stores information about a JWT token
type JWTTokenInfo struct {
	TokenID      string    `json:"jti"`
	InstanceName string    `json:"instance_name"`
	Label        string    `json:"label"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	UsageCount   int       `json:"usage_count"`
	Revoked      bool      `json:"revoked"`
}

var (
	defaultJWTManager *JWTTokenManager
	jwtManagerOnce    sync.Once
)

// InitJWTTokenManager initializes the JWT token manager
func InitJWTTokenManager(connString string, jwtSecret []byte) (*JWTTokenManager, error) {
	var err error

	jwtManagerOnce.Do(func() {
		var db *sql.DB
		
		// Connect to PostgreSQL
		db, err = sql.Open("pgx", connString)
		if err != nil {
			err = fmt.Errorf("failed to connect to database: %w", err)
			return
		}

		// Verify connection
		if err = db.Ping(); err != nil {
			db.Close()
			err = fmt.Errorf("database connection failed: %w", err)
			return
		}

		// Set connection pool parameters
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)

		// Create token manager
		defaultJWTManager = &JWTTokenManager{
			db:        db,
			jwtSecret: jwtSecret,
		}

		// Initialize database schema
		if err = defaultJWTManager.initializeSchema(); err != nil {
			db.Close()
			err = fmt.Errorf("failed to initialize schema: %w", err)
			return
		}

		// Start cleanup routine for expired tokens
		go defaultJWTManager.startCleanupRoutine()
	})

	return defaultJWTManager, err
}

// GetJWTTokenManager returns the JWT token manager instance
func GetJWTTokenManager() *JWTTokenManager {
	if defaultJWTManager == nil {
		// Try to initialize with environment variables if not initialized yet
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		if len(jwtSecret) == 0 {
			jwtSecret = []byte("default-secret-change-in-production")
		}
		
		pgConnString := os.Getenv("PG_CONNECTION_STRING")
		if pgConnString == "" {
			pgConnString = "postgres://postgres:postgres@localhost:5432/pgwatch?sslmode=disable"
		}
		
		_, err := InitJWTTokenManager(pgConnString, jwtSecret)
		if err != nil {
			// Fall back to memory-only mode if database connection fails
			defaultJWTManager = &JWTTokenManager{
				jwtSecret: jwtSecret,
			}
		}
	}
	return defaultJWTManager
}

// initializeSchema creates the necessary tables if they don't exist
func (tm *JWTTokenManager) initializeSchema() error {
	// Skip if no database connection
	if tm.db == nil {
		return nil
	}

	schema := `
	CREATE TABLE IF NOT EXISTS jwt_tokens (
		jti VARCHAR(255) PRIMARY KEY,
		instance_name VARCHAR(255) NOT NULL,
		label VARCHAR(255) NOT NULL,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		last_used_at TIMESTAMP,
		usage_count INTEGER NOT NULL DEFAULT 0,
		revoked BOOLEAN NOT NULL DEFAULT false
	);
	
	CREATE INDEX IF NOT EXISTS idx_jwt_tokens_instance ON jwt_tokens(instance_name);
	CREATE INDEX IF NOT EXISTS idx_jwt_tokens_expires ON jwt_tokens(expires_at);
	`

	_, err := tm.db.Exec(schema)
	return err
}

// GenerateToken creates a new JWT token for an instance
func (tm *JWTTokenManager) GenerateToken(instanceName, label string, expiresInDays int) (string, error) {
	// Create token expiration
	expiresAt := time.Now().Add(time.Hour * 24 * time.Duration(expiresInDays))
	
	// Create unique token ID
	jti := uuid.New().String()
	
	// Create JWT token with claims
	claims := TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        jti,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expiresAt.Unix(),
		},
		InstanceName: instanceName,
		Label:        label,
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Sign the token
	tokenString, err := token.SignedString(tm.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	
	// Store token in database if available
	if tm.db != nil {
		_, err = tm.db.Exec(
			"INSERT INTO jwt_tokens (jti, instance_name, label, created_at, expires_at, usage_count) VALUES ($1, $2, $3, $4, $5, $6)",
			jti,
			instanceName,
			label,
			time.Now(),
			expiresAt,
			0,
		)
		if err != nil {
			return "", fmt.Errorf("failed to store token: %w", err)
		}
	}
	
	return tokenString, nil
}

// IsTokenValid validates a JWT token and returns validity status and instance name
func (tm *JWTTokenManager) IsTokenValid(tokenString string) (bool, string) {
	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.jwtSecret, nil
	})
	
	if err != nil || !token.Valid {
		return false, ""
	}
	
	// Extract claims
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return false, ""
	}

	// Check revocation status if database is available
	if tm.db != nil {
		var revoked bool
		err = tm.db.QueryRow("SELECT revoked FROM jwt_tokens WHERE jti = $1", claims.Id).Scan(&revoked)
		
		if err != nil || revoked {
			return false, ""
		}
		
		// Update usage statistics
		go tm.recordUsage(claims.Id)
	}
	
	// Return validity and instance name
	return true, claims.InstanceName
}

// ValidateTokenWithDetails validates a JWT token and returns detailed information
func (tm *JWTTokenManager) ValidateTokenWithDetails(tokenString string) (*JWTTokenInfo, error) {
	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrJWTInvalidSignature
		}
		return tm.jwtSecret, nil
	})
	
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, ErrJWTExpired
			}
		}
		return nil, err
	}
	
	// Extract claims
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, ErrJWTMissingClaim
	}

	// If no database, return basic info from JWT
	if tm.db == nil {
		return &JWTTokenInfo{
			TokenID:      claims.Id,
			InstanceName: claims.InstanceName,
			Label:        claims.Label,
			CreatedAt:    time.Unix(claims.IssuedAt, 0),
			ExpiresAt:    time.Unix(claims.ExpiresAt, 0),
		}, nil
	}
	
	// Get full token info from database
	var info JWTTokenInfo
	err = tm.db.QueryRow(`
		SELECT jti, instance_name, label, created_at, expires_at, 
		       COALESCE(last_used_at, created_at) as last_used_at, 
		       usage_count, revoked 
		FROM jwt_tokens 
		WHERE jti = $1
	`, claims.Id).Scan(
		&info.TokenID, 
		&info.InstanceName, 
		&info.Label,
		&info.CreatedAt, 
		&info.ExpiresAt, 
		&info.LastUsedAt, 
		&info.UsageCount, 
		&info.Revoked,
	)
	
	if err != nil {
		return nil, ErrJWTDatabaseError
	}
	
	if info.Revoked {
		return nil, ErrJWTRevoked
	}
	
	// Update usage statistics
	go tm.recordUsage(claims.Id)
	
	return &info, nil
}

// RevokeToken revokes a JWT token
func (tm *JWTTokenManager) RevokeToken(tokenString string) error {
	// Parse token without validating signature
	token, _ := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tm.jwtSecret, nil
	})
	
	if token == nil {
		return errors.New("invalid token format")
	}
	
	// Extract claims
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return errors.New("invalid token claims")
	}
	
	// If no database, we can't revoke tokens
	if tm.db == nil {
		return errors.New("database connection required for token revocation")
	}
	
	// Mark token as revoked in database
	result, err := tm.db.Exec("UPDATE jwt_tokens SET revoked = true WHERE jti = $1", claims.Id)
	if err != nil {
		return err
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rows == 0 {
		return errors.New("token not found in database")
	}
	
	return nil
}

// ListTokens returns a list of all tokens from the database
func (tm *JWTTokenManager) ListTokens() ([]JWTTokenInfo, error) {
	if tm.db == nil {
		return nil, errors.New("database connection required to list tokens")
	}
	
	rows, err := tm.db.Query(`
		SELECT jti, instance_name, label, created_at, expires_at, 
		       COALESCE(last_used_at, created_at) as last_used_at, 
		       usage_count, revoked 
		FROM jwt_tokens
		ORDER BY created_at DESC
	`)
	
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var tokens []JWTTokenInfo
	for rows.Next() {
		var token JWTTokenInfo
		err := rows.Scan(
			&token.TokenID, 
			&token.InstanceName, 
			&token.Label, 
			&token.CreatedAt, 
			&token.ExpiresAt, 
			&token.LastUsedAt, 
			&token.UsageCount, 
			&token.Revoked,
		)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	
	return tokens, nil
}

// GetTokenInfo retrieves information about a specific token
func (tm *JWTTokenManager) GetTokenInfo(tokenID string) (*JWTTokenInfo, error) {
	if tm.db == nil {
		return nil, errors.New("database connection required to get token info")
	}
	
	var info JWTTokenInfo
	err := tm.db.QueryRow(`
		SELECT jti, instance_name, label, created_at, expires_at, 
		       COALESCE(last_used_at, created_at) as last_used_at, 
		       usage_count, revoked 
		FROM jwt_tokens 
		WHERE jti = $1
	`, tokenID).Scan(
		&info.TokenID, 
		&info.InstanceName, 
		&info.Label,
		&info.CreatedAt, 
		&info.ExpiresAt, 
		&info.LastUsedAt, 
		&info.UsageCount, 
		&info.Revoked,
	)
	
	if err != nil {
		return nil, err
	}
	
	return &info, nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (tm *JWTTokenManager) CleanupExpiredTokens() (int64, error) {
	if tm.db == nil {
		return 0, nil
	}
	
	result, err := tm.db.Exec("DELETE FROM jwt_tokens WHERE expires_at < $1", time.Now())
	if err != nil {
		return 0, err
	}
	
	return result.RowsAffected()
}

// recordUsage updates token usage statistics
func (tm *JWTTokenManager) recordUsage(jti string) {
	if tm.db == nil {
		return
	}
	
	_, err := tm.db.Exec(`
		UPDATE jwt_tokens 
		SET last_used_at = $1, usage_count = usage_count + 1 
		WHERE jti = $2
	`, time.Now(), jti)
	
	if err != nil {
		// Just log the error, don't fail the operation
		fmt.Fprintf(os.Stderr, "Failed to update token usage stats: %v\n", err)
	}
}

// startCleanupRoutine starts a background routine to clean up expired tokens
func (tm *JWTTokenManager) startCleanupRoutine() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		count, err := tm.CleanupExpiredTokens()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to clean up expired tokens: %v\n", err)
		} else if count > 0 {
			fmt.Fprintf(os.Stdout, "Cleaned up %d expired tokens\n", count)
		}
	}
}

// Close closes the database connection
func (tm *JWTTokenManager) Close() error {
	if tm.db != nil {
		return tm.db.Close()
	}
	return nil
}