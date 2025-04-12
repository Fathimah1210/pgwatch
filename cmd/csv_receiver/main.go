package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"time"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
)

type Config struct {
	Port          string
	StorageFolder string
	Token         string
	TLSCert       string
	TLSKey        string
}

func main() {
	cfg := parseConfig()
	
	// Initialize token manager
	auth.InitTokenManager(map[string]bool{
		cfg.Token: true, // Initial token
	})

	// Create receiver
	receiver := NewCSVReceiver(cfg.StorageFolder)
	server := NewAuthenticatedWrapper(receiver, cfg.Token)

	// Register RPC service
	rpc.RegisterName("Receiver", server)
	rpc.HandleHTTP()

	// Start server
	listener, err := createListener(cfg)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	log.Printf("Server started on %s", listener.Addr())
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func createListener(cfg Config) (net.Listener, error) {
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, err
		}
		
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		return tls.Listen("tcp", ":"+cfg.Port, tlsConfig)
	}
	return net.Listen("tcp", ":"+cfg.Port)
}

func parseConfig() Config {
	var cfg Config
	flag.StringVar(&cfg.Port, "port", "5050", "RPC server port")
	flag.StringVar(&cfg.StorageFolder, "rootFolder", "./data", "Storage folder for CSV files")
	flag.StringVar(&cfg.Token, "token", "", "Authentication token")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key file")
	flag.Parse()

	if cfg.Token == "" {
		log.Fatal("Authentication token is required")
	}
	return cfg
}