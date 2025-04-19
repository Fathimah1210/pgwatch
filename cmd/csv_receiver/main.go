package main

import (
	"log"
	"os"
	"path/filepath"
)

func main() {
	// Parse configuration
	cfg := ParseConfig()
	
	// Initialize directories
	if err := os.MkdirAll(cfg.StorageFolder, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}
	
	// Configure token storage based on authentication mode
	if !cfg.UseJWT {
		// Legacy token mode - use file-based storage
		tokenFilePath := filepath.Join(cfg.StorageFolder, "tokens.json")
		
		// For backward compatibility with existing code
		auth := getAuthPackage() // This would be the imported auth package
		
		// Set the storage path for file-based token storage
		auth.GetTokenManager().SetStoragePath(tokenFilePath)
		
		// Try to load existing tokens
		if err := auth.GetTokenManager().LoadTokens(); err != nil {
			log.Printf("Warning: Failed to load tokens: %v", err)
		}
		
		// Enable auto-save
		auth.GetTokenManager().EnableAutoSave(true)
	}
	
	// Start the server
	if err := StartServer(cfg); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// This is just a stub to make the code compile
// In the real implementation, this would be the imported auth package
func getAuthPackage() interface{} {
	return nil
}