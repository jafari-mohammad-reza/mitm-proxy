package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

type CertHandler struct {
	conf   *Conf
	logger ILogger
	cert   *tls.Certificate
}

func NewCertHandler(conf *Conf, logger ILogger) *CertHandler {
	return &CertHandler{
		conf:   conf,
		logger: logger,
	}
}
func (c *CertHandler) Init() error {
	_, err := os.Stat(c.conf.Cert.Path)
	if os.IsNotExist(err) {
		c.logger.Info("Creating CA certificate file:", c.conf.Cert.Path)
		cert, err := c.generateCA()
		if err != nil {
			return err
		}
		c.cert = cert
	}
	cert, err := tls.LoadX509KeyPair(c.conf.Cert.Path, c.conf.Cert.PrivateKey)
	if err != nil {
		return err
	}
	c.cert = &cert
	return nil
}

func (c *CertHandler) generateCA() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Go MITM Root CA",
			Organization: []string{"My Proxy CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// save the CA and private key to file
	if err := os.WriteFile(c.conf.Cert.Path, certPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(c.conf.Cert.PrivateKey, keyPEM, 0644); err != nil {
		return nil, err
	}
	return &tlsCert, nil
}
func (c *CertHandler) getLeafCert(sni string) (*tls.Certificate, error) {}
func (c *CertHandler) generateLeafCert(sni string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	parent, err := x509.ParseCertificate(c.cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0), // valid 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{sni},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, parent, &priv.PublicKey, c.cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}
