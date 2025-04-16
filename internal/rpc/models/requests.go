package models

// AuthRequest wraps an RPC request with authentication
type AuthRequest struct {
	Token string      `json:"token"`
	Data  interface{} `json:"data"`
}

// SyncRequest represents a metric sync request
type SyncRequest struct {
	DBUnique   string `json:"db_unique"`
	MetricName string `json:"metric_name"`
	Operation  string `json:"operation"`
}

// MeasurementEnvelope represents a batch of measurements
type MeasurementEnvelope struct {
	DBName     string      `json:"db_name"`
	MetricName string      `json:"metric_name"`
	Data       interface{} `json:"data"`
	CustomTags interface{} `json:"custom_tags,omitempty"`
}

// Response represents a generic RPC response
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}