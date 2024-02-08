package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	DefaultTimeout               = 30 * time.Second
	DefaultKeepAlive             = 30 * time.Second
	DefaultMaxIdleConns          = 100
	DefaultIdleConnTimeout       = 90 * time.Second
	DefaultExpectContinueTimeout = 1 * time.Second
	DefaultTLSHandshakeTimeout   = 10 * time.Second
)

func TransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}

func HTTPSGet(ctx context.Context, rootCAPool *x509.CertPool, certPEM []byte, privKeyPEM []byte,
	url string) (*[]byte, error) {
	// Convert to TLS cert
	clientCert, xerr := tls.X509KeyPair(certPEM, privKeyPEM)
	if xerr != nil {
		return nil, fmt.Errorf("failed X509KeyPair: %w", xerr)
	}

	// setup client & make request
	clientTLSConf := tls.Config{
		RootCAs:      rootCAPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// called after normal certificate verification, client cert is in verified first
			// do custom verification here
			return nil
		},
	}

	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: TransportDialContext(&net.Dialer{
			Timeout:   DefaultTimeout,
			KeepAlive: DefaultKeepAlive,
		}),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          DefaultMaxIdleConns,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		ExpectContinueTimeout: DefaultExpectContinueTimeout,
		TLSClientConfig:       &clientTLSConf,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
	}

	client := http.DefaultClient
	client.Transport = &transport

	request, qerr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if qerr != nil {
		return nil, fmt.Errorf("failed NewRequestWithContext: %w", qerr)
	}

	resp, derr := client.Do(request)
	if derr != nil {
		return nil, fmt.Errorf("failed Do: %w", derr)
	}

	defer resp.Body.Close()

	respBodyBytes, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("failed ReadAll: %w", rerr)
	}

	return &respBodyBytes, nil
}
