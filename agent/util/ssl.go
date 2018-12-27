package util

import (
	"fmt"
	"strings"
	"github.com/subutai-io/agent/lib/exec"
	"github.com/subutai-io/agent/log"
	"io/ioutil"
	"bytes"
	"path"
	"os"
	"crypto/rsa"
	"math/big"
	"time"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"crypto/rand"
	"github.com/subutai-io/agent/config"
)

var sslPath = path.Join(config.Agent.DataPrefix, "ssl")

//Validates separate certificate and private key
func ValidatePem(pathToCert, pathToKey string) bool {
	publicKeyFromCert, err := exec.ExecuteWithBash(fmt.Sprintf("openssl x509 -pubkey -noout -in %s", pathToCert))
	if log.Check(log.DebugLevel, "Validating OpenSSL x509 certificate", err) {
		return false
	}

	publicKeyFromPrivateKey, err := exec.ExecuteWithBash(fmt.Sprintf("openssl pkey -pubout -in %s", pathToKey))
	if log.Check(log.DebugLevel, "Validating private key", err) {
		return false
	}

	if strings.TrimSpace(publicKeyFromCert) != strings.TrimSpace(publicKeyFromPrivateKey) {
		log.Debug("Certificate does not match private key")

		return false
	}

	return true
}

// ParsePem return parsed OpenSSL x509 certificate.
func ParsePem(cert string) (crt, key []byte, err error) {
	key, err = exec.ExecB("openssl", "pkey", "-in", cert)
	if err == nil {
		f, err := ioutil.ReadFile(cert)
		if err == nil {
			crt = bytes.Replace(f, key, []byte(""), -1)
		}
	}
	return crt, key, err
}

func PublicCert() string {
	pemCerts, err := ioutil.ReadFile(path.Join(sslPath, "cert.pem"))
	if log.Check(log.WarnLevel, "Checking cert.pem file", err) {
		return ""
	}
	return string(pemCerts)
}

func generateCertNKey() error {
	hostname, err := os.Hostname()
	if log.Check(log.DebugLevel, "Getting Resource Host hostname", err) {
		return err
	}
	host := []string{hostname}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if log.Check(log.DebugLevel, "Generating private key", err) {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if log.Check(log.DebugLevel, "Generating serial number", err) {
		return err
	}

	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Subutai Foundation"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              host,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if log.Check(log.DebugLevel, "Creating certificate", err) {
		return err
	}

	if log.Check(log.DebugLevel, "Creating directory for SSL certificates", os.MkdirAll(sslPath, 0700)) {
		return err
	}

	certOut, err := os.Create(path.Join(sslPath, "cert.pem"))
	if log.Check(log.DebugLevel, "Opening cert.pem for writing", err) {
		os.Remove(path.Join(sslPath, "cert.pem"))
		return err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if log.Check(log.DebugLevel, "Encoding certificate", err) {
		os.Remove(path.Join(sslPath, "cert.pem"))
		return err
	}
	log.Check(log.DebugLevel, "Closing certificate", certOut.Close())

	keyOut, err := os.OpenFile(path.Join(sslPath, "key.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if log.Check(log.DebugLevel, "Opening key.pem for writing", err) {
		os.Remove(path.Join(sslPath, "cert.pem"))
		os.Remove(path.Join(sslPath, "key.pem"))
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if log.Check(log.DebugLevel, "Encoding certificate key", err) {
		os.Remove(path.Join(sslPath, "cert.pem"))
		os.Remove(path.Join(sslPath, "key.pem"))
		return err
	}
	log.Check(log.DebugLevel, "Closing certificate key", keyOut.Close())

	return nil
}
