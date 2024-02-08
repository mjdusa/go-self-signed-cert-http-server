package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/mjdusa/go-self-signed-cert-http-server/pkg/cert"
	"github.com/mjdusa/go-self-signed-cert-http-server/pkg/http/client"
)

const (
	CASerialNumber = 1965
	CAYearsValid   = 10
	PrivateKeyBits = 4096
)

func main() {
	Example()
}

// based loosly on https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
// WARNING: This is not a production ready example. It is for educational purposes only.
// WARNING / NOTICE: Some of thes steps could be optimized by changing the order of operations,
//   DON'T do it, it changes the behavior of the code and will break the cert creation process.

func Example() {
	now := time.Now().UTC()
	notBefore := now
	notAfter := now.AddDate(1, 0, 0) // 1 year from now
	caSerNbr := cert.CreateSerialNumber(CASerialNumber)
	serverSerNbr := cert.CreateSerialNumber(now.Year() - 1)

	subject, err := cert.CreateSubject(
		[]string{"Go Example Company, Inc."},
		[]string{"US"},
		[]string{"IA"},
		[]string{"Cedar Rapids"},
		[]string{"123 Main Street"},
		[]string{"52401"})
	if err != nil {
		panic(err)
	}

	// create CA cert
	// caCert, caCertBytes, caPEM, caPrivKey, caPrivKeyPEM, err :=
	//   cert.CreateSelfSignedCA(PrivateKeyBits, caSerNbr, subject, notBefore, notBefore.AddDate(10, 0, 0))
	caCert, _, _, caPrivKey, _, err := cert.CreateSelfSignedCA(
		PrivateKeyBits, caSerNbr, subject, notBefore, notBefore.AddDate(CAYearsValid, 0, 0))
	if err != nil {
		panic(err)
	}

	// create server cert
	// cert, certBytes, certPEM, privKey, privKeyPEM, err :=
	//   cert.CreateSelfSignedCertificate(caCert, caPrivKey, PrivateKeyBits, serverSerNbr, subject, notBefore, notAfter)
	_, _, serverPEM, _, serverPrivKeyPEM, err := cert.CreateSelfSignedCertificate(
		caCert, caPrivKey, PrivateKeyBits, serverSerNbr, subject, notBefore, notAfter)
	if err != nil {
		panic(err)
	}

	// Convert to TLS cert
	serverCert, err := tls.X509KeyPair(serverPEM.Bytes(), serverPrivKeyPEM.Bytes())
	if err != nil {
		panic(err)
	}

	clientSerNbr := cert.CreateSerialNumber(now.Year())

	// create client cert
	// cert, certBytes, certPEM, privKey, privKeyPEM, err :=
	//   cert.CreateSelfSignedCertificate(caCert, caPrivKey, PrivateKeyBits, clientSerNbr, subject, notBefore, notAfter)
	_, _, clientPEM, _, clientPrivKeyPEM, err := cert.CreateSelfSignedCertificate(
		caCert, caPrivKey, PrivateKeyBits, clientSerNbr, subject, notBefore, notAfter)
	if err != nil {
		panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	// alternatively, you can use AppendCertsFromPEM, but it is not as efficient as AddCert
	// caCertPool.AppendCertsFromPEM(caPEM.Bytes())

	// setup server & start
	serverTLSConf := &tls.Config{
		RootCAs:      caCertPool.Clone(),
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool.Clone(),
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// called after normal certificate verification, client cert is in verified first
			// do custom verification here
			return nil
		},
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success!")
	}))

	server.TLS = serverTLSConf
	server.StartTLS()
	defer server.Close()

	ctx := context.Background()
	respBody, herr := client.HTTPSGet(ctx, caCertPool.Clone(), clientPEM.Bytes(), clientPrivKeyPEM.Bytes(), server.URL)
	if herr != nil {
		panic(herr)
	}

	body := strings.TrimSpace(string(*respBody))
	if body != "success!" {
		panic("not successful!")
	}
	fmt.Println(body)
}
