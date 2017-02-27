// Package config provides configurable variables to other packages, sets logging level, defines global repository accessibility, etc.
package config

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/subutai-io/agent/log"

	"strings"

	"gopkg.in/gcfg.v1"
)

var client *http.Client
var version = ""

type agentConfig struct {
	Debug       bool
	GpgUser     string
	AppPrefix   string
	LxcPrefix   string
	DataPrefix  string
	GpgPassword string
}
type managementConfig struct {
	Host          string
	Port          string
	Secret        string
	GpgUser       string
	RestPublicKey string
	Fingerprint   string
	Allowinsecure bool
}

type influxdbConfig struct {
	Server string
	Db     string
	User   string
	Pass   string
}
type cdnConfig struct {
	Allowinsecure bool
	URL           string
	SSLport       string
	Kurjun        string
}
type templateConfig struct {
	Branch  string
	Version string
	Arch    string
}
type configFile struct {
	Agent      agentConfig
	Management managementConfig
	Influxdb   influxdbConfig
	CDN        cdnConfig
	Template   templateConfig
}

const defaultConfig = `
	[agent]
	gpgUser =
	gpgPassword = 12345678
	debug = true
	appPrefix = /apps/subutai/current/
	dataPrefix = /var/lib/apps/subutai/current/
	lxcPrefix = /mnt/lib/lxc/

	[management]
	gpgUser =
	port = 8443
	host =
	secret = secret
	restPublicKey = /rest/v1/security/keyman/getpublickeyring
	allowinsecure = true

    [cdn]
    url = cdn.subut.ai
    sslport = 8338
    allowinsecure = false

	[influxdb]
	server =
	user = root
	pass = root
	db = metrics

	[template]
	version = 4.0.0
	branch =
	arch = amd64
`

var (
	config configFile
	// Agent describes configuration options that used for configuring Subutai Agent
	Agent agentConfig
	// Management describes configuration options that used for accessing Subutai Management server
	Management managementConfig
	// Influxdb describes configuration options for InluxDB server
	Influxdb influxdbConfig
	// CDN url and port
	CDN cdnConfig
	// Template describes template configuration options
	Template templateConfig
)

func init() {
	log.Level(log.InfoLevel)

	err := gcfg.ReadStringInto(&config, defaultConfig)
	log.Check(log.InfoLevel, "Loading default config ", err)
	log.Check(log.DebugLevel, "Opening Agent default configuration file", gcfg.ReadFileInto(&config, "/apps/subutai/current/etc/agent.gcfg"))

	confpath := "/var/lib/apps/subutai/current/"
	if _, err := os.Stat(confpath); os.IsNotExist(err) {
		confpath = "/var/snap/" + os.Getenv("SNAP_NAME") + "/current/"
		config.Agent.AppPrefix = "/snap/" + os.Getenv("SNAP_NAME") + "/current/"
		config.Agent.LxcPrefix = "/var/snap/" + os.Getenv("SNAP_NAME") + "/common/lxc/"
		config.Agent.DataPrefix = "/var/snap/" + os.Getenv("SNAP_NAME") + "/current/"
		config.CDN.URL = strings.TrimPrefix(os.Getenv("SNAP_NAME"), "subutai-") + "cdn.subut.ai"
		config.Template.Branch = strings.TrimPrefix(os.Getenv("SNAP_NAME"), "subutai-")
		config.Template.Version = strings.TrimSuffix(version, "-SNAPSHOT")
	}
	log.Check(log.ErrorLevel, "Saving default configuration file", SaveDefaultConfig(confpath+"agent.gcfg"))
	log.Check(log.DebugLevel, "Opening Agent configuration file "+confpath+"agent.gcfg", gcfg.ReadFileInto(&config, confpath+"agent.gcfg"))

	if config.Agent.GpgUser == "" {
		config.Agent.GpgUser = "rh@subutai.io"
	}
	Agent = config.Agent
	Influxdb = config.Influxdb
	Template = config.Template
	Management = config.Management
	CDN = config.CDN
}

// InitAgentDebug turns on Debug output for the Subutai Agent.
func InitAgentDebug() {
	if config.Agent.Debug {
		log.Level(log.DebugLevel)
	}
}

// CheckKurjun checks if the Kurjun node available.
func CheckKurjun() (*http.Client, error) {
	// _, err := net.DialTimeout("tcp", Management.Host+":8339", time.Duration(2)*time.Second)
	client := &http.Client{}
	if config.CDN.Allowinsecure {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client = &http.Client{Transport: tr}
	}
	// if !log.Check(log.InfoLevel, "Trying local repo", err) {
	// Cdn.Kurjun = "https://" + Management.Host + ":8339/rest/kurjun"
	// } else {
	_, err := net.DialTimeout("tcp", CDN.URL+":"+CDN.SSLport, time.Duration(2)*time.Second)
	for c := 0; err != nil && c < 5; _, err = net.DialTimeout("tcp", CDN.URL+":"+CDN.SSLport, time.Duration(2)*time.Second) {
		log.Info("CDN unreachable, retrying")
		time.Sleep(3 * time.Second)
		c++
	}
	if log.Check(log.WarnLevel, "Checking CDN accessibility", err) {
		return nil, err
	}

	CDN.Kurjun = "https://" + CDN.URL + ":" + CDN.SSLport + "/kurjun/rest"
	if !CDN.Allowinsecure {
		client = &http.Client{}
	}
	// }
	return client, nil
}

// SaveDefaultConfig saves agent configuration file for future changes by user.
// It's use build in defaultConfig constant as a source.
func SaveDefaultConfig(conf string) error {
	if _, err := os.Stat(conf); err == nil {
		return nil
	}

	f, err := os.Create(conf)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	c := reflect.ValueOf(&config).Elem()
	for i := 0; i < c.NumField(); i++ {
		_, err := fmt.Fprintln(w, "["+c.Type().Field(i).Name+"]")
		if err != nil {
			return err
		}
		for j := 0; j < c.Field(i).NumField(); j++ {
			_, err = fmt.Fprintln(w, c.Field(i).Type().Field(j).Name, "=", c.Field(i).Field(j).Interface())
			if err != nil {
				return err
			}

		}
		_, err = fmt.Fprintln(w)
		if err != nil {
			return err
		}
	}
	w.Flush()
	return nil
}
