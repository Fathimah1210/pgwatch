package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
	rpcauth "github.com/cybertec-postgresql/pgwatch/v3/internal/rpc/auth"
)

// StartServer initializes and starts the RPC server
func StartServer(cfg Config) error {
	// Initialize audit logger
	auditLogger, err := auth.InitAuditLogger(cfg.AuditLogFile)
	if err != nil {
		return fmt.Errorf("failed to initialize audit logger: %w", err)
	}
	defer auditLogger.Close()
	
	// Initialize token manager based on configuration
	if cfg.UseJWT {
		// Use JWT token manager with PostgreSQL
		jwtSecret := []byte(cfg.JWTSecret)
		if len(jwtSecret) == 0 {
			jwtSecret = []byte("default-secret-change-in-production")
			log.Println("WARNING: Using default JWT secret. This is not secure for production.")
		}
		
		// Initialize JWT token manager
		jwtManager, err := auth.InitJWTTokenManager(cfg.PGConnString, jwtSecret)
		if err != nil {
			return fmt.Errorf("failed to initialize JWT token manager: %w", err)
		}
		defer jwtManager.Close()
		
		// If initial token is provided, create a JWT token for it
		if cfg.Token != "" {
			// Create initial JWT token (instance name is "default" for backward compatibility)
			_, err := jwtManager.GenerateToken("default", "Initial token", 0) // No expiration
			if err != nil {
				log.Printf("Warning: Failed to create initial JWT token: %v", err)
			}
		}
		
		// Set environment variable to signal use of JWT
		os.Setenv("USE_JWT_AUTH", "true")
		
	} else {
		// Use original token manager
		initialTokens := make(map[string]bool)
		if cfg.Token != "" {
			initialTokens[cfg.Token] = true
		}
		auth.InitTokenManager(initialTokens)

		// Set environment variable to use legacy token manager
		os.Setenv("USE_JWT_AUTH", "false")
	}
	
	// Create receiver
	receiver := NewCSVReceiver(cfg.StorageFolder)
	defer receiver.Close()
	
	// Create authenticated wrapper
	server := rpcauth.NewAuthenticatedWrapper(receiver, cfg.Token, cfg.InsecureMode)
	
	// Register RPC service
	rpc.RegisterName("Receiver", server)
	rpc.HandleHTTP()
	
	// Create listener
	listener, err := createListener(cfg)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	
	// Set up graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	
	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		authMode := "legacy"
		if cfg.UseJWT {
			authMode = "JWT+PostgreSQL"
		}
		log.Printf("Server started on %s (auth mode: %s, secure mode: %v)", 
			listener.Addr(), authMode, !cfg.InsecureMode)
		serverErr <- http.Serve(listener, nil)
	}()
	
	// Wait for shutdown or error
	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case <-shutdown:
		log.Println("Shutting down gracefully...")
		return listener.Close()
	}
}

// Create listener based on configuration
func createListener(cfg Config) (net.Listener, error) {
	// Use TLS if certificate and key are provided
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		
		return tls.Listen("tcp", ":"+cfg.Port, tlsConfig)
	}
	
	// Use regular TCP listener otherwise
	return net.Listen("tcp", ":"+cfg.Port)
}