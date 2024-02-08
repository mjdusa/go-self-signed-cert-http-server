package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	IPv4Loopback  = "127.0.0.1"
	Certificate   = "CERTIFICATE"
	RSAPrivateKey = "RSA PRIVATE KEY"
)

// WARNING / NOTICE: Some of these steps could be optimized by changing the order of operations.
//                   DON'T change the order, it can change the behavior of the code and break the cert created.

func CreateSerialNumber(nbr int) *big.Int {
	return big.NewInt(int64(nbr))
}

func CreateSubject(organization, country, province, locality, streetAddress, postalCode []string) (pkix.Name, error) {
	name := pkix.Name{
		Organization:  organization,
		Country:       country,
		Province:      province,
		Locality:      locality,
		StreetAddress: streetAddress,
		PostalCode:    postalCode,
	}
	return name, nil
}

func CreatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed GenerateKey: %w", err)
	}

	return key, nil
}

func PEMEncodeBlock(blockType string, byArray []byte) (*bytes.Buffer, error) {
	buffer := new(bytes.Buffer)
	block := pem.Block{
		Type:  blockType,
		Bytes: byArray,
	}

	if err := pem.Encode(buffer, &block); err != nil {
		return nil, fmt.Errorf("failed Encode: %w", err)
	}

	return buffer, nil
}

func createCertWithRSA(privateKeyBits int, template *x509.Certificate, parent *x509.Certificate,
	caPrivKey *rsa.PrivateKey) (*x509.Certificate, []byte, *bytes.Buffer, *rsa.PrivateKey, *bytes.Buffer, error) {
	fail := func(err error) (*x509.Certificate, []byte, *bytes.Buffer, *rsa.PrivateKey, *bytes.Buffer, error) {
		return nil, []byte{}, nil, nil, nil, fmt.Errorf("failed: %w", err)
	}

	// gen private key
	privKey, pkErr := CreatePrivateKey(privateKeyBits)
	if pkErr != nil {
		return fail(pkErr)
	}

	if caPrivKey == nil {
		caPrivKey = privKey
	}

	// create certificate
	certBytes, cErr := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, caPrivKey)
	if cErr != nil {
		return fail(cErr)
	}

	// PEM encode certificate
	certPEM, ecErr := PEMEncodeBlock(Certificate, certBytes)
	if ecErr != nil {
		return fail(ecErr)
	}

	// PEM encode private key
	privKeyPEM, peErr := PEMEncodeBlock(RSAPrivateKey, x509.MarshalPKCS1PrivateKey(privKey))
	if peErr != nil {
		return fail(peErr)
	}

	// parse certificate bytes to x509.Certificate
	cert, pcErr := x509.ParseCertificate(certBytes)
	if pcErr != nil {
		return fail(pcErr)
	}

	return cert, certBytes, certPEM, privKey, privKeyPEM, nil
}

func CreateSelfSignedCA(privateKeyBits int, serialNumber *big.Int, subject pkix.Name, notBefore,
	notAfter time.Time) (*x509.Certificate, []byte, *bytes.Buffer, *rsa.PrivateKey, *bytes.Buffer, error) {
	// define CA certificate template
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return createCertWithRSA(privateKeyBits, template, template, nil)
}

func CreateSelfSignedCertificate(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey, privateKeyBits int,
	serialNumber *big.Int, subject pkix.Name, notBefore, notAfter time.Time) (*x509.Certificate,
	[]byte, *bytes.Buffer, *rsa.PrivateKey, *bytes.Buffer, error) {
	// define certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         false,
		IPAddresses:  []net.IP{net.ParseIP(IPv4Loopback), net.IPv6loopback},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return createCertWithRSA(privateKeyBits, template, caCert, caPrivKey)
}
