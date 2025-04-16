package main

import (
	"log"
)

func main() {
	// Parse configuration
	cfg := ParseConfig()
	
	// Start server
	if err := StartServer(cfg); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}