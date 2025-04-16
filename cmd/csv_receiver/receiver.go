package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CSVReceiver stores metrics data in CSV files
type CSVReceiver struct {
	rootFolder string
	mu         sync.Mutex
	files      map[string]*os.File
	writers    map[string]*csv.Writer
}

// NewCSVReceiver creates a new CSV receiver
func NewCSVReceiver(rootFolder string) *CSVReceiver {
	return &CSVReceiver{
		rootFolder: rootFolder,
		files:      make(map[string]*os.File),
		writers:    make(map[string]*csv.Writer),
	}
}

// UpdateMeasurements processes and stores metrics data
func (r *CSVReceiver) UpdateMeasurements(data interface{}, reply *string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Convert data to a measurement envelope
	envelope, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid data format")
	}
	
	// Extract metrics information
	dbName, _ := envelope["db_name"].(string)
	metricName, _ := envelope["metric_name"].(string)
	
	if dbName == "" || metricName == "" {
		return fmt.Errorf("missing required fields")
	}
	
	// Create file if it doesn't exist
	fileKey := dbName + "_" + metricName
	writer, exists := r.writers[fileKey]
	if !exists {
		if err := r.createWriter(fileKey); err != nil {
			return err
		}
		writer = r.writers[fileKey]
	}
	
	// Convert data to CSV rows
	rows, err := convertToCSVRows(envelope)
	if err != nil {
		return err
	}
	
	// Write rows
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV: %w", err)
		}
	}
	
	// Flush writer
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("error flushing CSV: %w", err)
	}
	
	*reply = fmt.Sprintf("Stored %d rows for %s/%s", len(rows), dbName, metricName)
	return nil
}

// SyncMetric handles metric synchronization requests
func (r *CSVReceiver) SyncMetric(data interface{}, reply *string) error {
	// Handle sync operations
	syncData, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid sync data format")
	}
	
	dbUnique, _ := syncData["db_unique"].(string)
	metricName, _ := syncData["metric_name"].(string)
	operation, _ := syncData["operation"].(string)
	
	*reply = fmt.Sprintf("Sync successful: %s/%s/%s", dbUnique, metricName, operation)
	return nil
}

// Create a new CSV writer for the given key
func (r *CSVReceiver) createWriter(fileKey string) error {
	// Create file path
	fileName := fmt.Sprintf("%s_%s.csv", fileKey, time.Now().Format("20060102"))
	filePath := filepath.Join(r.rootFolder, fileName)
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Open file
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	
	// Create CSV writer
	writer := csv.NewWriter(file)
	
	// Store file and writer
	r.files[fileKey] = file
	r.writers[fileKey] = writer
	
	log.Printf("Created CSV file: %s", filePath)
	return nil
}

// Convert measurement data to CSV rows
func convertToCSVRows(data map[string]interface{}) ([][]string, error) {
	// This is a simple implementation - enhance as needed
	rows := [][]string{}
	
	// Add header row if needed
	// rows = append(rows, []string{"timestamp", "metric", "value", "tags"})
	
	// Process measurement data
	measurements, ok := data["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid measurements format")
	}
	
	for _, m := range measurements {
		measurement, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Create a row for each measurement
		row := []string{
			time.Now().Format(time.RFC3339),
			data["metric_name"].(string),
			fmt.Sprintf("%v", measurement),
		}
		
		rows = append(rows, row)
	}
	
	return rows, nil
}

// Close closes all open files
func (r *CSVReceiver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	for key, writer := range r.writers {
		writer.Flush()
		r.files[key].Close()
		delete(r.writers, key)
		delete(r.files, key)
	}
}