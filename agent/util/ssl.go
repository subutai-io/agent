package util

import (
	"fmt"
	"strings"
	"github.com/subutai-io/agent/lib/exec"
	"github.com/subutai-io/agent/log"
	"io/ioutil"
	"bytes"
)

//Validates separate certificate and private key
func ValidatePem2(pathToCert, pathToKey string) bool {
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
func ParsePem(cert string) (crt, key []byte) {
	key, err := exec.ExecB("openssl", "pkey", "-in", cert)
	if !log.Check(log.ErrorLevel, "Parsing private key", err) {
		f, err := ioutil.ReadFile(cert)
		if !log.Check(log.ErrorLevel, "Reading cert "+cert, err) {
			crt = bytes.Replace(f, key, []byte(""), -1)
		}
	}
	return crt, key
}

func ParsePem2(cert string) (crt, key []byte, err error) {
	key, err = exec.ExecB("openssl", "pkey", "-in", cert)
	if err == nil {
		f, err := ioutil.ReadFile(cert)
		if err == nil {
			crt = bytes.Replace(f, key, []byte(""), -1)
		}
	}
	return crt, key, err
}
