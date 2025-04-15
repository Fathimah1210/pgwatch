package sinks

import (
	"context"
	"errors"
	"net/rpc"
	"net/url"
	"strings"
	"time"

	"github.com/cybertec-postgresql/pgwatch/v3/internal/auth_helper"
	"github.com/cybertec-postgresql/pgwatch/v3/internal/log"
	"github.com/cybertec-postgresql/pgwatch/v3/internal/metrics"
)

const (
	defaultRPCTimeout = 30 * time.Second
	maxRetries        = 3
	retryDelay        = 1 * time.Second
)

type RPCConfig struct {
	Address     string
	Token       string
	Timeout     time.Duration
	MaxRetries  int
	RetryDelay  time.Duration
}

type RPCWriter struct {
	ctx      context.Context
	config   RPCConfig
	client   *rpc.Client
	stopChan chan struct{}
}

func NewRPCWriter(ctx context.Context, address string) (*RPCWriter, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}

	token := ""
	if u.User != nil {
		token = u.User.Username()
	}
	cleanAddr := u.Host

	config := RPCConfig{
		Address:    cleanAddr,
		Token:      token,
		Timeout:    defaultRPCTimeout,
		MaxRetries: maxRetries,
		RetryDelay: retryDelay,
	}

	return &RPCWriter{
		ctx:      ctx,
		config:   config,
		stopChan: make(chan struct{}),
	}, nil
}

func (rw *RPCWriter) connect() error {
	var err error
	for i := 0; i < rw.config.MaxRetries; i++ {
		rw.client, err = rpc.DialHTTP("tcp", rw.config.Address)
		if err == nil {
			return nil
		}
		
		select {
		case <-time.After(rw.config.RetryDelay):
			continue
		case <-rw.ctx.Done():
			return rw.ctx.Err()
		case <-rw.stopChan:
			return errors.New("connection aborted")
		}
	}
	return err
}

func (rw *RPCWriter) Write(msgs []metrics.MeasurementMessage) error {
	if err := rw.connect(); err != nil {
		return err
	}
	defer rw.client.Close()

	for _, msg := range msgs {
		authReq := auth_helper.AuthRequest{
			Token: rw.config.Token,
			Data:  msg,
		}

		var logMsg string
		err := rw.client.Call("Receiver.UpdateMeasurements", &authReq, &logMsg)
		if err != nil {
			if shouldRetry(err) {
				return rw.Write(msgs) // Retry
			}
			return err
		}
	}
	return nil
}

func shouldRetry(err error) bool {
	return strings.Contains(err.Error(), "connection refused") || 
	       strings.Contains(err.Error(), "timeout")
}