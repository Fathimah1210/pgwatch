package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
)

// Config holds the CSV receiver configuration
type Config struct {
	Port          string
	StorageFolder string
	
	// Authentication settings
	UseJWT          bool   // Whether to use JWT tokens instead of simple tokens
	Token           string // Legacy token (for backward compatibility)
	JWTSecret       string // Secret for JWT token signing
	PGConnString    string // PostgreSQL connection string for token storage
	
	// Security settings
	TLSCert       string
	TLSKey        string
	AuditLogFile  string
	InsecureMode  bool
}

// ParseConfig parses command line flags and environment variables
func ParseConfig() Config {
	var cfg Config
	
	// Basic settings
	flag.StringVar(&cfg.Port, "port", getEnvWithDefault("CSV_RECEIVER_PORT", "5050"), "RPC server port")
	flag.StringVar(&cfg.StorageFolder, "storage", getEnvWithDefault("CSV_STORAGE_FOLDER", "./data"), "Storage folder for CSV files")
	
	// Authentication settings
	flag.BoolVar(&cfg.UseJWT, "jwt", getEnvBool("USE_JWT_AUTH", false), "Use JWT tokens with PostgreSQL instead of simple tokens")
	flag.StringVar(&cfg.Token, "token", os.Getenv("CSV_AUTH_TOKEN"), "Authentication token (legacy mode)")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", os.Getenv("JWT_SECRET"), "Secret for JWT token signing")
	flag.StringVar(&cfg.PGConnString, "pg-conn", os.Getenv("PG_CONNECTION_STRING"), "PostgreSQL connection string for token storage")
	
	// Security settings
	flag.BoolVar(&cfg.InsecureMode, "insecure", getEnvBool("CSV_INSECURE_MODE", false), "Allow running without authentication (not recommended)")
	flag.StringVar(&cfg.TLSCert, "tls-cert", os.Getenv("CSV_TLS_CERT"), "TLS certificate file")
	flag.StringVar(&cfg.TLSKey, "tls-key", os.Getenv("CSV_TLS_KEY"), "TLS private key file")
	flag.StringVar(&cfg.AuditLogFile, "audit-log", getEnvWithDefault("CSV_AUDIT_LOG", "./logs/auth.log"), "Audit log file location")
	
	flag.Parse()
	
	// Validate configuration
	if !cfg.InsecureMode {
		if !cfg.UseJWT && cfg.Token == "" {
			log.Fatal("Authentication token is required in legacy mode. Use -insecure flag to run without authentication (not recommended)")
		}
		
		if cfg.UseJWT && cfg.JWTSecret == "" {
			log.Println("Warning: No JWT secret provided, using a default secret (not secure for production)")
		}
	}
	
	if cfg.InsecureMode {
		log.Println("WARNING: Running in insecure mode. Authentication is disabled!")
	}
	
	// Create directories if they don't exist
	if err := os.MkdirAll(cfg.StorageFolder, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}
	
	if cfg.AuditLogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.AuditLogFile), 0755); err != nil {
			log.Fatalf("Failed to create audit log directory: %v", err)
		}
	}
	
	return cfg
}

// Helper function to get environment variable with default
func getEnvWithDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Helper function to get boolean environment variable
func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		return value == "1" || value == "true" || value == "yes"
	}
	return defaultValue
}