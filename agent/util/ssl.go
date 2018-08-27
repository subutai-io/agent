package util

import (
	"fmt"
	"strings"
	"github.com/subutai-io/agent/lib/exec"
	"github.com/subutai-io/agent/log"
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
