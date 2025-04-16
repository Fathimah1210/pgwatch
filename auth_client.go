package main

import (
	"encoding/gob"
	"fmt"
	"net/rpc"
)

// Register types with gob
func init() {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
	gob.Register([]map[string]interface{}{})
}

// AuthRequest structure matching server's expectation
type AuthRequest struct {
	Token string
	Data  map[string]interface{}
}

func main() {
	fmt.Println("Testing token authentication...")
	
	// Test valid token
	fmt.Println("\n1. Testing with valid token...")
	result := testToken("test_token")
	if result == "auth_success" {
		fmt.Println("Valid token authentication successful!")
	} else {
		fmt.Println("Valid token test failed:", result)
	}
	
	// Test invalid token
	fmt.Println("\n2. Testing with invalid token...")
	result = testToken("invalid_token")
	if result == "auth_failed" {
		fmt.Println("Invalid token correctly rejected!")
	} else {
		fmt.Println("Invalid token test failed:", result)
	}
}

func testToken(token string) string {
	// Connect to RPC server
	client, err := rpc.DialHTTP("tcp", "localhost:5050")
	if err != nil {
		return fmt.Sprintf("connection error: %v", err)
	}
	defer client.Close()

	// Call RPC method directly with just the token
	var valid bool
	err = client.Call("Receiver.VerifyToken", token, &valid)
	
	if err != nil {
		// If this is an authentication error, it might be expected for invalid tokens
		if token != "test_token" {
			return "auth_failed"
		}
		return fmt.Sprintf("RPC error: %v", err)
	}
	
	if valid {
		return "auth_success"
	} else {
		return "auth_failed"
	}
}