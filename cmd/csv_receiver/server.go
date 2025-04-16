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
	
	// Initialize token manager
	if cfg.Token != "" {
		auth.InitTokenManager(map[string]bool{
			cfg.Token: true,
		})
	} else {
		auth.InitTokenManager(nil)
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
		log.Printf("Server started on %s (secure mode: %v)", listener.Addr(), !cfg.InsecureMode)
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