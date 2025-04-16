package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/metrics"
	"github.com/cybertec-postgresql/pgwatch/v3/internal/sinks"
)

func main() {
	// Create context
	ctx := context.Background()

	// Test with valid token
	fmt.Println("Testing with valid token...")
	testValidToken(ctx)

	// Give the server some time to process
	time.Sleep(1 * time.Second)

	// Test with invalid token
	fmt.Println("\nTesting with invalid token...")
	testInvalidToken(ctx)
}

func testValidToken(ctx context.Context) {
	// Create RPC writer with valid token
	rpcWriter, err := sinks.NewRPCWriter(ctx, "rpc://test_token@localhost:5050")
	if err != nil {
		log.Fatalf("Failed to create RPC writer: %v", err)
	}

	// Create sample metrics
	metricData := metrics.Measurements{
		{
			"usage_percent": 42.5,
			"epoch_ns":      time.Now().UnixNano(),
		},
	}

	envelopes := []metrics.MeasurementEnvelope{
		{
			DBName:     "test_db",
			MetricName: "cpu_usage",
			Data:       metricData,
		},
	}

	// Send metrics
	err = rpcWriter.Write(envelopes)
	if err != nil {
		log.Fatalf("Failed to send metrics with valid token: %v", err)
	}
	fmt.Println("Successfully sent metrics with valid token")

	// Test metric sync
	err = rpcWriter.SyncMetric("test_db", "cpu_usage", "add")
	if err != nil {
		log.Fatalf("Failed to sync metric with valid token: %v", err)
	}
	fmt.Println("Successfully synced metric with valid token")
}

func testInvalidToken(ctx context.Context) {
	// Create RPC writer with invalid token
	rpcWriter, err := sinks.NewRPCWriter(ctx, "rpc://invalid_token@localhost:5050")
	if err != nil {
		log.Fatalf("Failed to create RPC writer: %v", err)
	}

	// Create sample metrics
	metricData := metrics.Measurements{
		{
			"usage_percent": 42.5,
			"epoch_ns":      time.Now().UnixNano(),
		},
	}

	envelopes := []metrics.MeasurementEnvelope{
		{
			DBName:     "test_db",
			MetricName: "cpu_usage",
			Data:       metricData,
		},
	}

	// Send metrics (should fail)
	err = rpcWriter.Write(envelopes)
	if err == nil {
		log.Fatal("Expected error when sending metrics with invalid token")
	}
	fmt.Printf("Got expected error with invalid token: %v\n", err)

	// Test metric sync (should fail)
	err = rpcWriter.SyncMetric("test_db", "cpu_usage", "add")
	if err == nil {
		log.Fatal("Expected error when syncing metric with invalid token")
	}
	fmt.Printf("Got expected error with invalid token: %v\n", err)
}