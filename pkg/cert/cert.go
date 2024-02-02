package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

const (
	Certificate   = "CERTIFICATE"
	RSAPrivateKey = "RSA PRIVATE KEY"
)

// based loosly on https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
// WARNING: This is not a production ready example. It is for educational purposes only.
// WARNING / NOTICE: Some of thes steps could be optimized by changing the order of operations, DON'T do it, it changes the behavior of the code and will break the cert creation process.

func Example() {
	now := time.Now().UTC()
	caSerNbr := CreateSerialNumber(1965)
	certSerNbr := CreateSerialNumber(now.Year())

	subject, err := CreateSubject([]string{"Go Example Company, Inc."}, []string{"US"}, []string{"IA"}, []string{"Cedar Rapids"}, []string{"123 Main Street"}, []string{"52401"})
	if err != nil {
		panic(err)
	}

	//caCert, caPEM, caPrivKey, caPrivKeyPEM, err := CreateCA(caSerNbr, subject, now, now.AddDate(10, 0, 0))
	caCert, caPEM, caPrivKey, _, err := CreateCA(caSerNbr, subject, now, now.AddDate(10, 0, 0))
	if err != nil {
		panic(err)
	}

	notAfter := now.AddDate(1, 0, 0) // 1 year from now
	//certificate, certPEM, certPrivKey, certPrivKeyPEM, err := CreateCertificate(caCert, caPrivKey, certSerNbr, subject, now, notAfter)
	_, certPEM, _, certPrivKeyPEM, err := CreateCertificate(caCert, caPrivKey, certSerNbr, subject, now, notAfter)
	if err != nil {
		panic(err)
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		panic(err)
	}

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caPEM.Bytes())

	clientTLSConf := &tls.Config{
		RootCAs: caCertPool,
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success!")
	}))

	server.TLS = serverTLSConf
	server.StartTLS()
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}

	http := http.Client{
		Transport: transport,
	}

	resp, err := http.Get(server.URL)
	if err != nil {
		panic(err)
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body == "success!" {
		fmt.Println(body)
	} else {
		panic("not successful!")
	}
}

func CreateSerialNumber(nbr int) *big.Int {
	return big.NewInt(int64(nbr))
}

func CreateSubject(organization, country, province, locality, streetAddress, postalCode []string) (pkix.Name, error) {
	return pkix.Name{
		Organization:  organization,
		Country:       country,
		Province:      province,
		Locality:      locality,
		StreetAddress: streetAddress,
		PostalCode:    postalCode,
	}, nil
}

func CreatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, bits); err != nil {
		return nil, err
	} else {
		return key, nil
	}
}

func PEMEncodeBlock(blockType string, byArray []byte) (*bytes.Buffer, error) {
	buffer := new(bytes.Buffer)
	block := pem.Block{
		Type:  blockType,
		Bytes: byArray,
	}

	if err := pem.Encode(buffer, &block); err != nil {
		return nil, err
	}

	return buffer, nil
}

func CreateCA(serialNumber *big.Int, subject pkix.Name, notBefore, notAfter time.Time) (*x509.Certificate, *bytes.Buffer, *rsa.PrivateKey, *bytes.Buffer, error) {
	// define CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// gen private key
	privKey, pkErr := CreatePrivateKey(4096)
	if pkErr != nil {
		return nil, nil, nil, nil, pkErr
	}

	// create CA certificate
	certBytes, cErr := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privKey.PublicKey, privKey)
	if cErr != nil {
		return nil, nil, nil, nil, cErr
	}

	// PEM encode CA certificate
	pem, ecErr := PEMEncodeBlock(Certificate, certBytes)
	if ecErr != nil {
		return nil, nil, nil, nil, ecErr
	}

	// PEM encode private key
	privKeyPEM, pErr := PEMEncodeBlock(RSAPrivateKey, x509.MarshalPKCS1PrivateKey(privKey))
	if pErr != nil {
		return nil, nil, nil, nil, pErr
	}

	// parse CA certificate bytes to x509.Certificate
	caCert, pcErr := x509.ParseCertificate(certBytes)
	if pcErr != nil {
		return nil, nil, nil, nil, pcErr
	}

	return caCert, pem, privKey, privKeyPEM, nil
}

func CreateCertificate(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey, serialNumber *big.Int, subject pkix.Name, notBefore, notAfter time.Time) (*x509.Certificate, *bytes.Buffer, *rsa.PrivateKey, *bytes.Buffer, error) {
	// define certificate
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         false,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// gen private key
	privKey, pkErr := CreatePrivateKey(4096)
	if pkErr != nil {
		return nil, nil, nil, nil, pkErr
	}

	// create certificate
	certBytes, ccErr := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &privKey.PublicKey, caPrivKey)
	if ccErr != nil {
		return nil, nil, nil, nil, ccErr
	}

	// PEM encode certificate
	pem, ceErr := PEMEncodeBlock(Certificate, certBytes)
	if ceErr != nil {
		return nil, nil, nil, nil, ceErr
	}

	// PEM encode private key
	privKeyPEM, peErr := PEMEncodeBlock(RSAPrivateKey, x509.MarshalPKCS1PrivateKey(privKey))
	if peErr != nil {
		return nil, nil, nil, nil, peErr
	}

	// parse certificate bytes to x509.Certificate
	certificate, pcErr := x509.ParseCertificate(certBytes)
	if pcErr != nil {
		return nil, nil, nil, nil, pcErr
	}

	return certificate, pem, privKey, privKeyPEM, nil
}
