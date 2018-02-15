// Package utils contains several function with different purposes which are needed by other packages
package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"github.com/influxdata/influxdb/client/v2"
	"io"
	"net"
)

var (
	influxDbClient client.Client
)

// Iface describes network interfaces of the Resource Host.
type Iface struct {
	InterfaceName string `json:"interfaceName"`
	IP            string `json:"ip"`
}

// ---> InfluxDB
func InfluxDbClient() (clnt client.Client, err error) {

	if influxDbClient == nil {
		influxDbClient, err = createInfluxDbClient()
	}

	clnt = influxDbClient

	return
}

func ResetInfluxDbClient() {
	if influxDbClient != nil {
		influxDbClient.Close()
		influxDbClient = nil
	}
}

func createInfluxDbClient() (client.Client, error) {

	return client.NewHTTPClient(client.HTTPConfig{
		Addr:               "https://" + config.Influxdb.Server + ":8086",
		Username:           config.Influxdb.User,
		Password:           config.Influxdb.Pass,
		Timeout:            time.Second * 60,
		InsecureSkipVerify: true,
	})

}

// <--- InfluxDb

func Close(resp *http.Response) {
	if resp.Body != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}
}

// PublicCert returns Public SSL certificate for Resource Host
func PublicCert() string {
	pemCerts, err := ioutil.ReadFile(config.Agent.DataPrefix + "ssl/cert.pem")
	if log.Check(log.WarnLevel, "Checking cert.pem file", err) {
		return ""
	}
	return string(pemCerts)
}

// InstanceType returns type of the Resource host: EC2 or LOCAL
func InstanceType() string {
	uuid, err := ioutil.ReadFile("/sys/hypervisor/uuid")
	if !log.Check(log.DebugLevel, "Checking if AWS ec2 by reading /sys/hypervisor/uuid", err) {
		if strings.HasPrefix(string(uuid), "ec2") {
			return "EC2"
		}
	}
	return "LOCAL"
}

// TLSConfig provides HTTP client for Bi-directional SSL connection with Management server.
func TLSConfig() *http.Client {
	tlsconfig := newTLSConfig()
	for tlsconfig == nil || len(tlsconfig.Certificates[0].Certificate) == 0 {
		time.Sleep(time.Second * 2)
		for PublicCert() == "" {
			x509generate()
		}
		tlsconfig = newTLSConfig()
	}

	transport := &http.Transport{
		TLSClientConfig: tlsconfig,
		IdleConnTimeout: time.Minute,
		MaxIdleConns:    10,
	}

	return &http.Client{Transport: transport, Timeout: time.Second * 10}
}

func x509generate() {
	hostname, err := os.Hostname()
	log.Check(log.DebugLevel, "Getting Resource Host hostname", err)
	host := []string{hostname}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if log.Check(log.WarnLevel, "Generating private key", err) {
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if log.Check(log.WarnLevel, "Generating serial number", err) {
		return
	}

	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Subutai Social Foundation"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              host,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if log.Check(log.WarnLevel, "Creating certificate", err) {
		return
	}

	log.Check(log.DebugLevel, "Creating directory for SSL certificates", os.MkdirAll(config.Agent.DataPrefix+"ssl", 0700))

	certOut, err := os.Create(config.Agent.DataPrefix + "ssl/cert.pem")
	if log.Check(log.WarnLevel, "Opening cert.pem for writing", err) {
		return
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Check(log.DebugLevel, "Encoding certificate", err)
	log.Check(log.DebugLevel, "Closing certificate", certOut.Close())

	keyOut, err := os.OpenFile(config.Agent.DataPrefix+"ssl/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if log.Check(log.WarnLevel, "Opening key.pem for writing", err) {
		return
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	log.Check(log.DebugLevel, "Encoding certificate key", err)
	log.Check(log.DebugLevel, "Closing certificate key", keyOut.Close())

}

func newTLSConfig() *tls.Config {
	clientCert, err := ioutil.ReadFile(config.Agent.DataPrefix + "ssl/cert.pem")
	if log.Check(log.WarnLevel, "Checking cert.pem file", err) {
		return nil
	}
	privateKey, err := ioutil.ReadFile(config.Agent.DataPrefix + "ssl/key.pem")
	if log.Check(log.WarnLevel, "Checking key.pem file", err) {
		return nil
	}

	cert, err := tls.X509KeyPair(clientCert, privateKey)
	if log.Check(log.WarnLevel, "Loading x509 keypair", err) {
		return nil
	}

	if len(cert.Certificate) != 0 {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if log.Check(log.WarnLevel, "Parsing client certificates", err) {
			return nil
		}
	}

	if config.Management.Allowinsecure {
		// Create tls.Config with desired tls properties
		return &tls.Config{
			ClientAuth:         tls.NoClientCert,
			ClientCAs:          nil,
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}

	}
	return &tls.Config{ClientAuth: tls.NoClientCert, ClientCAs: nil, Certificates: []tls.Certificate{cert}}
}

//HTTP CLIENT

func GetClient(allowInsecure bool, timeoutSec int) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecure}}
	return &http.Client{Transport: tr, Timeout: time.Second * time.Duration(timeoutSec)}
}

//one-shot client for one long lasting request
//no keep-alive, 1 idle connection per client
//new client must be used for each new request
func GetClientForUploadDownload() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Dial:                  timeoutDialer(time.Second*15, time.Hour*5),
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			DisableKeepAlives:     true,
			MaxIdleConns:          1,
			MaxIdleConnsPerHost:   1,
			IdleConnTimeout:       time.Second * 5,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: config.CDN.Allowinsecure},
		},
	}
}

func timeoutDialer(connectTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, connectTimeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, nil
	}
}

// CheckCDN checks if the Kurjun node available.
func CheckCDN() {

	address := config.CDN.URL + ":" + config.CDN.SSLport
	_, err := net.DialTimeout("tcp", address, time.Duration(5)*time.Second)

	for c := 0; err != nil && c < 5; _, err = net.DialTimeout("tcp", address, time.Duration(5)*time.Second) {
		log.Info("CDN unreachable, retrying")
		time.Sleep(3 * time.Second)
		c++
	}

	log.Check(log.ErrorLevel, "Checking CDN accessibility", err)
}
