package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// NewCertificateRequest makes the certificate key (ECDSA P-256, separate
// from the device key) and a CSR for it (section 6). It returns the key as
// PKCS#8 DER, for safe keeping, and the CSR as DER. The CSR's subject is
// ignored by the server.
func NewCertificateRequest() (keyDER, csrDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if keyDER, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return nil, nil, err
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return keyDER, csrDER, err
}

// ClientCertificate pairs a certificate (DER) with its PKCS#8 key and
// checks that they belong together.
func ClientCertificate(certDER, keyDER []byte) (*tls.Certificate, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("certificate key is not ECDSA")
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&ec.PublicKey) {
		return nil, errors.New("certificate does not match its key")
	}
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: ec, Leaf: cert}, nil
}
