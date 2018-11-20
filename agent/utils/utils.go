// Package utils contains several function with different purposes which are needed by other packages
package utils

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"github.com/influxdata/influxdb/client/v2"
	"io"
	"regexp"
	"path"
	"fmt"
	"strconv"
)

var (
	sslPath = path.Join(config.Agent.DataPrefix, "ssl")
)

// ---> InfluxDB
func InfluxDbClient() (clnt client.Client, err error) {
	return client.NewHTTPClient(client.HTTPConfig{
		Addr:               "https://" + path.Join(config.ManagementIP) + ":8086",
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
//todo move to ssl
func PublicCert() string {
	pemCerts, err := ioutil.ReadFile(path.Join(sslPath, "cert.pem"))
	if log.Check(log.WarnLevel, "Checking cert.pem file", err) {
		return ""
	}
	return string(pemCerts)
}

// InstanceType returns type of the Resource host: EC2 or LOCAL
//todo add GCE
func InstanceType() string {
	uuid, err := ioutil.ReadFile("/sys/hypervisor/uuid")
	if !log.Check(log.DebugLevel, "Checking if AWS ec2 by reading /sys/hypervisor/uuid", err) {
		if strings.HasPrefix(string(uuid), "ec2") {
			return "EC2"
		}
	}
	return "LOCAL"
}

func GetClient(allowInsecure bool, timeoutSec int) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecure}}
	return &http.Client{Transport: tr, Timeout: time.Second * time.Duration(timeoutSec)}
}

func RetryGet(url string, clnt *http.Client, attempts int) (*http.Response, error) {
	var response *http.Response
	var err error
	var attempt = 0

	for response, err = clnt.Get(url); err != nil && attempt < attempts; response, err = clnt.Get(url) {
		attempt++
		time.Sleep(time.Duration(attempt*5) * time.Second)
	}

	return response, err
}

func VerifyLxcName(name string) {
	/*
	The labels must follow the rules for ARPANET host names.  They must
	start with a letter, end with a letter or digit, and have as interior
	characters only letters, digits, and hyphen.  There are also some
	restrictions on the length.  Labels must be 63 characters or less.
	*/

	hostnameRegex := regexp.MustCompile(`^[[:alpha:]][[:alnum:]\-]{0,61}[[:alnum:]]$`)
	singleLetterHostnameRegex := regexp.MustCompile(`^[[:alpha:]]$`)

	if len(name) == 1 {
		if !singleLetterHostnameRegex.MatchString(name) {
			log.Error(fmt.Sprintf("value '%s' does not match %s",
				name, singleLetterHostnameRegex.String()))
		}
	} else if !hostnameRegex.MatchString(name) {
		log.Error(fmt.Sprintf("value '%s' does not match %s",
			name, hostnameRegex.String()))
	}
}

func MatchRegexGroups(regEx *regexp.Regexp, url string) (paramsMap map[string]string) {

	match := regEx.FindStringSubmatch(url)

	paramsMap = make(map[string]string)
	for i, name := range regEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}
	return
}

//todo use HttpUtil instead
func GetConsolePubKey() []byte {
	clnt := GetClient(config.Management.AllowInsecure, 30)
	resp, err := clnt.Get("https://" + path.Join(config.ManagementIP) + ":" + config.Management.Port + config.Management.RestPublicKey)

	if err == nil {
		defer Close(resp)
	}

	if log.Check(log.WarnLevel, "Getting Console public Key", err) {
		return nil
	}

	if resp.StatusCode == 200 {
		if key, err := ioutil.ReadAll(resp.Body); err == nil {
			return key
		}
	}

	log.Warn("Failed to fetch Console public key. Status Code " + strconv.Itoa(resp.StatusCode))
	return nil
}
