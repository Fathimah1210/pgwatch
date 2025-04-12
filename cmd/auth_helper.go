package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth"
	"github.com/cybertec-postgresql/pgwatch/v3/sinks"
)

type AuthenticatedWrapper struct {
	receiver sinks.Receiver
	tm       *auth.TokenManager
	logger   *log.Logger
	timeout  time.Duration
}

func NewAuthenticatedWrapper(receiver sinks.Receiver, token string) *AuthenticatedWrapper {
	tm := auth.GetTokenManager()
	if token != "" {
		tm.AddToken(token) // Add initial token
	}
	
	return &AuthenticatedWrapper{
		receiver: receiver,
		tm:       tm,
		logger:   log.Default(),
		timeout:  5 * time.Second,
	}
}

func (aw *AuthenticatedWrapper) UpdateMeasurements(req *sinks.AuthRequest, logMsg *string) error {
	ctx, cancel := context.WithTimeout(context.Background(), aw.timeout)
	defer cancel()

	if !aw.tm.IsTokenValid(req.Token) {
		aw.logger.Printf("Invalid token attempt from client")
		return errors.New("authentication failed")
	}

	select {
	case err := <-aw.callReceiverAsync(req, logMsg):
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (aw *AuthenticatedWrapper) callReceiverAsync(req *sinks.AuthRequest, logMsg *string) <-chan error {
	errChan := make(chan error, 1)
	
	go func() {
		defer close(errChan)
		
		msg, ok := req.Data.(sinks.MeasurementMessage)
		if !ok {
			errChan <- errors.New("invalid data format")
			return
		}

		errChan <- aw.receiver.UpdateMeasurements(&msg, logMsg)
	}()
	
	return errChan
}