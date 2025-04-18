// Add to the main function after initializing token manager
tokenFilePath := filepath.Join(cfg.StorageFolder, "tokens.json")

// Set the storage path
auth.GetTokenManager().SetStoragePath(tokenFilePath)

// Try to load existing tokens
if err := auth.GetTokenManager().LoadTokens(); err != nil {
    log.Printf("Warning: Failed to load tokens: %v", err)
}

// Enable auto-save
auth.GetTokenManager().EnableAutoSave(true)