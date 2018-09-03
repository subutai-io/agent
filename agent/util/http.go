package util

import (
	http2 "net/http"
	"crypto/tls"
	"time"
	"io/ioutil"
	"crypto/x509"
	"path"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"crypto/rsa"
	"math/big"
	"crypto/x509/pkix"
	"os"
	"encoding/pem"
	"crypto/rand"
	"io"
	"strconv"
	"bytes"
	"github.com/subutai-io/agent/agent/vars"
)

const MaxIdleConnections = 10

var (
	sslPath       = path.Join(config.Agent.DataPrefix, "ssl")
	allowInsecure = config.Management.AllowInsecure
)

func init() {
	//precreate certs for secure client if missing
	if !ValidatePem2(path.Join(sslPath, "cert.pem"), path.Join(sslPath, "key.pem")) {
		log.Check(log.FatalLevel, "Generating PEM certificate", generateCertNKey())
	}
}

type HttpUtil struct {
}

func GetUtil() HttpUtil {
	return HttpUtil{}
}

func (http HttpUtil) Close(resp *http2.Response) {
	if resp.Body != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (http HttpUtil) GetClient(timeoutSec int) *http2.Client {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecure,},
		IdleConnTimeout: time.Minute,
		MaxIdleConns:    MaxIdleConnections,}

	return &http2.Client{Transport: tr, Timeout: time.Second * time.Duration(timeoutSec)}
}

func (http HttpUtil) GetSecureClient(timeoutSec int) (*http2.Client, error) {

	tlsConfig, err := newTLSConfig()

	if log.Check(log.WarnLevel, "Creating secure client for Console", err) {
		return nil, err
	}

	transport := &http2.Transport{
		TLSClientConfig:     tlsConfig,
		IdleConnTimeout:     time.Minute,
		MaxIdleConns:        MaxIdleConnections,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http2.Client{Transport: transport, Timeout: time.Second * time.Duration(timeoutSec),}, nil
}

func newTLSConfig() (*tls.Config, error) {

	clientCert, err := ioutil.ReadFile(path.Join(sslPath, "cert.pem"))
	if err != nil {
		return nil, err
	}

	privateKey, err := ioutil.ReadFile(path.Join(sslPath, "key.pem"))
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(clientCert, privateKey)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) != 0 {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
	}

	if vars.IsDaemon {
		buf := new(bytes.Buffer)
		var pemkey = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Leaf.Raw}
		pem.Encode(buf, pemkey)
		log.Debug(buf.String())
		log.Debug("SslPath is " + sslPath + " AllowInsecure is " + strconv.FormatBool(allowInsecure))
	}

	return &tls.Config{
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
		InsecureSkipVerify: allowInsecure,
		Certificates:       []tls.Certificate{cert},
	}, nil
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
