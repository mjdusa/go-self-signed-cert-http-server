package client

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
)

func HttpsGet(rootCAPool *x509.CertPool, certPEM []byte, privKeyPEM []byte, url string) (*[]byte, error) {
	// Convert to TLS cert
	clientCert, xerr := tls.X509KeyPair(certPEM, privKeyPEM)
	if xerr != nil {
		return nil, xerr
	}

	// setup client & make request
	clientTLSConf := &tls.Config{
		RootCAs:      rootCAPool,
		Certificates: []tls.Certificate{clientCert},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// called after normal certificate verification, client cert is in verified first
			// do custom verification here
			return nil
		},
	}

	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}

	client := http.Client{
		Transport: transport,
	}

	resp, gerr := client.Get(url)
	if gerr != nil {
		return nil, gerr
	}

	respBodyBytes, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, rerr
	}

	return &respBodyBytes, nil
}
