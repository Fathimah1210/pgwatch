package auth

import (
	"testing"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
	"github.com/cybertec-postgresql/pgwatch/v3/internal/rpc/models"
	"github.com/stretchr/testify/assert"
)

// MockReceiver implements the ReceiverInterface for testing
type MockReceiver struct {
	measurements map[string]interface{}
	syncRequests map[string]string
}

func NewMockReceiver() *MockReceiver {
	return &MockReceiver{
		measurements: make(map[string]interface{}),
		syncRequests: make(map[string]string),
	}
}

func (m *MockReceiver) UpdateMeasurements(data interface{}, reply *string) error {
	if data == nil {
		return assert.AnError
	}
	
	// Store the measurement for verification
	if envelope, ok := data.(map[string]interface{}); ok {
		if dbName, ok := envelope["db_name"].(string); ok {
			m.measurements[dbName] = data
			*reply = "Stored measurement for " + dbName
			return nil
		}
	}
	
	return assert.AnError
}

func (m *MockReceiver) SyncMetric(data interface{}, reply *string) error {
	if data == nil {
		return assert.AnError
	}
	
	// Store the sync request for verification
	if syncReq, ok := data.(map[string]interface{}); ok {
		if dbName, ok := syncReq["db_unique"].(string); ok {
			if metricName, ok := syncReq["metric_name"].(string); ok {
				key := dbName + ":" + metricName
				m.syncRequests[key] = syncReq["operation"].(string)
				*reply = "Synced " + key
				return nil
			}
		}
	}
	
	return assert.AnError
}

func TestAuthenticatedWrapper_ValidToken(t *testing.T) {
	// Initialize token manager with a valid token
	auth.InitTokenManager(map[string]bool{
		"valid_token": true,
	})
	
	// Create a mock receiver
	mockReceiver := NewMockReceiver()
	
	// Create the wrapper with authentication
	wrapper := NewAuthenticatedWrapper(mockReceiver, "valid_token", false)
	
	// Test UpdateMeasurements with valid token
	t.Run("UpdateMeasurements with valid token", func(t *testing.T) {
		var reply string
		req := &models.AuthRequest{
			Token: "valid_token",
			Data: map[string]interface{}{
				"db_name":     "test_db",
				"metric_name": "cpu",
				"data":        []interface{}{map[string]interface{}{"value": 42}},
			},
		}
		
		err := wrapper.UpdateMeasurements(req, &reply)
		assert.NoError(t, err)
		assert.Contains(t, reply, "test_db")
		assert.Contains(t, mockReceiver.measurements, "test_db")
	})
	
	// Test SyncMetric with valid token
	t.Run("SyncMetric with valid token", func(t *testing.T) {
		var reply string
		req := &models.AuthRequest{
			Token: "valid_token",
			Data: map[string]interface{}{
				"db_unique":   "test_db",
				"metric_name": "cpu",
				"operation":   "add",
			},
		}
		
		err := wrapper.SyncMetric(req, &reply)
		assert.NoError(t, err)
		assert.Contains(t, reply, "Synced")
		assert.Equal(t, "add", mockReceiver.syncRequests["test_db:cpu"])
	})
}

func TestAuthenticatedWrapper_InvalidToken(t *testing.T) {
	// Initialize token manager with a valid token
	auth.InitTokenManager(map[string]bool{
		"valid_token": true,
	})
	
	// Create a mock receiver
	mockReceiver := NewMockReceiver()
	
	// Create the wrapper with authentication
	wrapper := NewAuthenticatedWrapper(mockReceiver, "valid_token", false)
	
	// Test UpdateMeasurements with invalid token
	t.Run("UpdateMeasurements with invalid token", func(t *testing.T) {
		var reply string
		req := &models.AuthRequest{
			Token: "invalid_token",
			Data: map[string]interface{}{
				"db_name":     "test_db",
				"metric_name": "cpu",
				"data":        []interface{}{map[string]interface{}{"value": 42}},
			},
		}
		
		err := wrapper.UpdateMeasurements(req, &reply)
		assert.Error(t, err)
		assert.NotContains(t, mockReceiver.measurements, "test_db")
	})
	
	// Test SyncMetric with invalid token
	t.Run("SyncMetric with invalid token", func(t *testing.T) {
		var reply string
		req := &models.AuthRequest{
			Token: "invalid_token",
			Data: map[string]interface{}{
				"db_unique":   "test_db",
				"metric_name": "cpu",
				"operation":   "add",
			},
		}
		
		err := wrapper.SyncMetric(req, &reply)
		assert.Error(t, err)
		assert.NotContains(t, mockReceiver.syncRequests, "test_db:cpu")
	})
}

func TestAuthenticatedWrapper_InsecureMode(t *testing.T) {
	// Initialize token manager with a valid token
	auth.InitTokenManager(map[string]bool{
		"valid_token": true,
	})
	
	// Create a mock receiver
	mockReceiver := NewMockReceiver()
	
	// Create the wrapper with insecure mode enabled
	wrapper := NewAuthenticatedWrapper(mockReceiver, "valid_token", true)
	
	// Test UpdateMeasurements with invalid token but insecure mode
	t.Run("UpdateMeasurements in insecure mode", func(t *testing.T) {
		var reply string
		req := &models.AuthRequest{
			Token: "invalid_token", // Invalid token should still work in insecure mode
			Data: map[string]interface{}{
				"db_name":     "insecure_db",
				"metric_name": "cpu",
				"data":        []interface{}{map[string]interface{}{"value": 42}},
			},
		}
		
		err := wrapper.UpdateMeasurements(req, &reply)
		assert.NoError(t, err)
		assert.Contains(t, reply, "insecure_db")
		assert.Contains(t, mockReceiver.measurements, "insecure_db")
	})
}

func TestVerifyToken(t *testing.T) {
	// Initialize token manager with a valid token
	auth.InitTokenManager(map[string]bool{
		"valid_token": true,
	})
	
	// Create a mock receiver
	mockReceiver := NewMockReceiver()
	
	// Create the wrapper with authentication
	wrapper := NewAuthenticatedWrapper(mockReceiver, "valid_token", false)
	
	// Test VerifyToken with valid token
	t.Run("VerifyToken with valid token", func(t *testing.T) {
		var valid bool
		err := wrapper.VerifyToken("valid_token", &valid)
		assert.NoError(t, err)
		assert.True(t, valid)
	})
	
	// Test VerifyToken with invalid token
	t.Run("VerifyToken with invalid token", func(t *testing.T) {
		var valid bool
		err := wrapper.VerifyToken("invalid_token", &valid)
		assert.NoError(t, err)
		assert.False(t, valid)
	})
}