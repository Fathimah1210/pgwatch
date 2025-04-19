package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	
	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
)

func main() {
	// Define commands
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	
	createCmd := flag.NewFlagSet("create", flag.ExitOnError)
	createInstance := createCmd.String("instance", "", "Instance name (required)")
	createLabel := createCmd.String("label", "", "Human-readable label")
	createExpiry := createCmd.Int("expiry", 0, "Token expiry in days (0 = no expiry)")
	
	revokeCmd := flag.NewFlagSet("revoke", flag.ExitOnError)
	revokeToken := revokeCmd.String("token", "", "Token to revoke (required)")
	
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	verifyToken := verifyCmd.String("token", "", "Token to verify (required)")
	
	// Connection parameters
	jwtSecret := flag.String("secret", os.Getenv("JWT_SECRET"), "JWT secret key")
	pgConn := flag.String("pg-conn", os.Getenv("PG_CONNECTION_STRING"), "PostgreSQL connection string")
	
	// Check if we have any command
	if len(os.Args) < 2 {
		fmt.Println("Expected 'list', 'create', 'revoke', or 'verify' subcommand")
		fmt.Println("Usage:")
		fmt.Println("  token_manager [options] list")
		fmt.Println("  token_manager [options] create -instance NAME [-label LABEL] [-expiry DAYS]")
		fmt.Println("  token_manager [options] revoke -token TOKEN")
		fmt.Println("  token_manager [options] verify -token TOKEN")
		fmt.Println("\nOptions:")
		fmt.Println("  -secret SECRET       JWT secret key (env: JWT_SECRET)")
		fmt.Println("  -pg-conn CONNSTR     PostgreSQL connection string (env: PG_CONNECTION_STRING)")
		os.Exit(1)
	}
	
	// Check secret
	if *jwtSecret == "" {
		*jwtSecret = "default-secret-change-in-production"
		fmt.Println("WARNING: Using default JWT secret. This is not secure for production.")
	}
	
	// Initialize JWT token manager
	jwtManager, err := auth.InitJWTTokenManager(*pgConn, []byte(*jwtSecret))
	if err != nil {
		log.Fatalf("Failed to initialize JWT token manager: %v", err)
	}
	defer jwtManager.Close()
	
	// Process commands
	switch os.Args[1] {
	case "list":
		listCmd.Parse(os.Args[2:])
		listTokens(jwtManager)
		
	case "create":
		createCmd.Parse(os.Args[2:])
		if *createInstance == "" {
			fmt.Println("Error: -instance is required")
			createCmd.PrintDefaults()
			os.Exit(1)
		}
		createToken(jwtManager, *createInstance, *createLabel, *createExpiry)
		
	case "revoke":
		revokeCmd.Parse(os.Args[2:])
		if *revokeToken == "" {
			fmt.Println("Error: -token is required")
			revokeCmd.PrintDefaults()
			os.Exit(1)
		}
		revokeTokenCmd(jwtManager, *revokeToken)
		
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		if *verifyToken == "" {
			fmt.Println("Error: -token is required")
			verifyCmd.PrintDefaults()
			os.Exit(1)
		}
		verifyTokenCmd(jwtManager, *verifyToken)
		
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Expected 'list', 'create', 'revoke', or 'verify' subcommand")
		os.Exit(1)
	}
}

// listTokens lists all tokens in the database
func listTokens(jwtManager *auth.JWTTokenManager) {
	tokens, err := jwtManager.ListTokens()
	if err != nil {
		log.Fatalf("Failed to list tokens: %v", err)
	}
	
	if len(tokens) == 0 {
		fmt.Println("No tokens found")
		return
	}
	
	fmt.Println("Tokens:")
	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("%-36s %-15s %-20s %-10s\n", "TOKEN ID", "INSTANCE", "LABEL", "STATUS")
	fmt.Println("-----------------------------------------------------------")
	
	for _, token := range tokens {
		status := "ACTIVE"
		if token.Revoked {
			status = "REVOKED"
		} else if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(time.Now()) {
			status = "EXPIRED"
		}
		
		fmt.Printf("%-36s %-15s %-20s %-10s\n",
			token.TokenID,
			token.InstanceName,
			token.Label,
			status,
		)
	}
	fmt.Println("-----------------------------------------------------------")
}

// createToken creates a new token
func createToken(jwtManager *auth.JWTTokenManager, instance, label string, expiryDays int) {
	if label == "" {
		label = fmt.Sprintf("Token for %s", instance)
	}
	
	token, err := jwtManager.GenerateToken(instance, label, expiryDays)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	
	fmt.Println("Token created successfully")
	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("Instance: %s\n", instance)
	fmt.Printf("Label:    %s\n", label)
	if expiryDays > 0 {
		fmt.Printf("Expires:  In %d days\n", expiryDays)
	} else {
		fmt.Println("Expires:  Never")
	}
	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("TOKEN: %s\n", token)
	fmt.Println("-----------------------------------------------------------")
	fmt.Println("IMPORTANT: Save this token! It will not be displayed again.")
}

// revokeTokenCmd revokes a token
func revokeTokenCmd(jwtManager *auth.JWTTokenManager, token string) {
	err := jwtManager.RevokeToken(token)
	if err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}
	
	fmt.Println("Token revoked successfully")
}

// verifyTokenCmd verifies a token
func verifyTokenCmd(jwtManager *auth.JWTTokenManager, token string) {
	tokenInfo, err := jwtManager.ValidateTokenWithDetails(token)
	if err != nil {
		fmt.Printf("Token is INVALID: %v\n", err)
		return
	}
	
	fmt.Println("Token is VALID")
	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("Token ID:       %s\n", tokenInfo.TokenID)
	fmt.Printf("Instance:       %s\n", tokenInfo.InstanceName)
	fmt.Printf("Label:          %s\n", tokenInfo.Label)
	fmt.Printf("Created:        %s\n", tokenInfo.CreatedAt.Format(time.RFC3339))
	
	if !tokenInfo.ExpiresAt.IsZero() {
		fmt.Printf("Expires:        %s\n", tokenInfo.ExpiresAt.Format(time.RFC3339))
		if time.Now().After(tokenInfo.ExpiresAt) {
			fmt.Println("                (EXPIRED)")
		} else {
			fmt.Printf("                (in %s)\n", time.Until(tokenInfo.ExpiresAt).Round(time.Second))
		}
	} else {
		fmt.Println("Expires:        Never")
	}
	
	fmt.Printf("Last used:      %s\n", tokenInfo.LastUsedAt.Format(time.RFC3339))
	fmt.Printf("Usage count:    %d\n", tokenInfo.UsageCount)
	fmt.Println("-----------------------------------------------------------")
}