package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent represents a security-related event
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	Token      string    `json:"token,omitempty"` // Only store token hash if needed
	SourceIP   string    `json:"source_ip"`
	Success    bool      `json:"success"`
	Message    string    `json:"message,omitempty"`
	DBName     string    `json:"db_name,omitempty"`
	MetricName string    `json:"metric_name,omitempty"`
}

// AuditLogger handles logging security events
type AuditLogger struct {
	file    *os.File
	mu      sync.Mutex
	enabled bool
}

var (
	defaultLogger *AuditLogger
	loggerOnce    sync.Once
)

// InitAuditLogger initializes the audit logger
func InitAuditLogger(logPath string) (*AuditLogger, error) {
	var err error
	
	loggerOnce.Do(func() {
		if logPath == "" {
			defaultLogger = &AuditLogger{enabled: false}
			return
		}
		
		// Ensure directory exists
		dir := filepath.Dir(logPath)
		if err = os.MkdirAll(dir, 0755); err != nil {
			return
		}
		
		// Open log file
		var file *os.File
		file, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		
		defaultLogger = &AuditLogger{
			file:    file,
			enabled: true,
		}
	})
	
	return defaultLogger, err
}

// GetAuditLogger returns the singleton audit logger
func GetAuditLogger() *AuditLogger {
	if defaultLogger == nil {
		// Return a no-op logger
		return &AuditLogger{enabled: false}
	}
	return defaultLogger
}

// LogEvent logs an audit event
func (al *AuditLogger) LogEvent(event AuditEvent) error {
	if !al.enabled || al.file == nil {
		return nil
	}
	
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	al.mu.Lock()
	defer al.mu.Unlock()
	
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	
	_, err = al.file.Write(append(data, '\n'))
	return err
}

// LogAuthAttempt logs an authentication attempt
func (al *AuditLogger) LogAuthAttempt(token, sourceIP string, success bool, message string) {
	_ = al.LogEvent(AuditEvent{
		EventType: "auth_attempt",
		Token:     token, // Consider hashing this
		SourceIP:  sourceIP,
		Success:   success,
		Message:   message,
	})
}

// Close closes the audit log file
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}