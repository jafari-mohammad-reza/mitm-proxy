package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"time"
)

type CertHandler struct {
	conf     *Conf
	logger   ILogger
	cert     *tls.Certificate
	priv     *rsa.PrivateKey
	sniCerts map[string]*tls.Certificate
}

func NewCertHandler(conf *Conf, logger ILogger) *CertHandler {
	return &CertHandler{
		conf:     conf,
		logger:   logger,
		sniCerts: make(map[string]*tls.Certificate),
	}
}

func (c *CertHandler) Init() error {
	if _, err := os.Stat(c.conf.Cert.Path); os.IsNotExist(err) {
		c.logger.Info("Creating CA certificate:", c.conf.Cert.Path)
		cert, err := c.generateCA()
		if err != nil {
			return err
		}
		c.cert = cert
	}

	cert, err := tls.LoadX509KeyPair(c.conf.Cert.Path, c.conf.Cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load CA cert/key: %w", err)
	}
	c.cert = &cert

	keyPEM, err := os.ReadFile(c.conf.Cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read CA key file: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("invalid PEM block: expected RSA PRIVATE KEY")
	}
	c.priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse RSA key: %w", err)
	}

	dir, err := os.ReadDir(c.conf.Cert.CertsDir)
	if err != nil {
		return fmt.Errorf("failed to read certs dir: %w", err)
	}

	for _, file := range dir {
		if file.IsDir() {
			continue
		}

		if file.Name() == strings.Split(c.conf.Cert.Path, "/")[1] || file.Name() == strings.Split(c.conf.Cert.PrivateKey, "/")[1] {
			continue
		}
		fmt.Println(file.Name())
		path := c.conf.Cert.CertsDir + "/" + file.Name()
		sni := strings.TrimSuffix(file.Name(), ".pem")
		sniCert, err := tls.LoadX509KeyPair(path, c.conf.Cert.PrivateKey)
		if err != nil {
			c.logger.Error(fmt.Sprintf("Failed to load SNI cert for %s", sni), err)
			continue
		}
		c.sniCerts[sni] = &sniCert
	}

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
		NotAfter:              time.Now().AddDate(10, 0, 0),
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

	if err := os.WriteFile(c.conf.Cert.Path, certPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(c.conf.Cert.PrivateKey, keyPEM, 0600); err != nil {
		return nil, err
	}
	return &tlsCert, nil
}
func (c *CertHandler) getLeafCert(sni string) (*tls.Certificate, error) {
	cert, ok := c.sniCerts[sni]
	if ok {
		return cert, nil
	}
	ce, err := c.generateLeafCert(sni)
	if err != nil {
		return nil, err
	}
	c.sniCerts[sni] = ce
	return ce, nil
}
func (c *CertHandler) generateLeafCert(sni string) (*tls.Certificate, error) {

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
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{sni},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, parent, &c.priv.PublicKey, c.cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path.Join(c.conf.Cert.CertsDir, fmt.Sprintf("%s.pem", sni)), certPEM, 0644); err != nil {
		return nil, err
	}
	return &tlsCert, nil
}
