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
	"encoding/pem"
	"io"
	"strconv"
	"bytes"
	"github.com/subutai-io/agent/agent/vars"
)

const MaxIdleConnections = 10

var allowInsecure = config.Management.AllowInsecure

func init() {
	//precreate certs for secure client if missing
	if !ValidatePem(path.Join(sslPath, "cert.pem"), path.Join(sslPath, "key.pem")) {
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
