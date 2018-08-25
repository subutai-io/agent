// Package config provides configurable variables to other packages, sets logging level, defines global repository accessibility, etc.
package config

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"gopkg.in/gcfg.v1"

	"github.com/subutai-io/agent/log"
	"path"
)

const RhGpgUser = "rh@subutai.io"

type agentConfig struct {
	Debug         bool
	GpgUser       string
	LxcPrefix     string
	Dataset       string
	DataPrefix    string
	CacheDir      string
	GpgPassword   string
	GpgHome       string
	SshJumpServer string
}

type managementConfig struct {
	Host    string
	//TODO remove or add securePort
	Port    string
	Secret  string
	GpgUser string
	//TODO remove
	RestPublicKey string
	Fingerprint   string
	AllowInsecure bool
}

type influxdbConfig struct {
	Db   string
	User string
	Pass string
}

type cdnConfig struct {
	AllowInsecure       bool
	URL                 string
	SSLport             string
	IpfsPath            string
	TemplateDownloadUrl string
}

type configFile struct {
	Agent      agentConfig
	Management managementConfig
	Influxdb   influxdbConfig
	CDN        cdnConfig
}

const defaultConfig = `
	[agent]
	debug = true
	gpgUser =
	gpgPassword = 12345678
	gpgHome =
	dataPrefix = /var/lib/subutai/
	lxcPrefix = /var/lib/lxc/
    dataset = subutai/fs
    cacheDir = /var/cache/subutai
    sshJumpServer = cdn.subutai.io

	[management]
	host =
	port = 8443
	secret = secret
	gpgUser =
	restPublicKey = /rest/v1/security/keyman/getpublickeyring
    fingerprint =
	allowInsecure = true

	[influxdb]
	db = metrics
	user = root
	pass = root

    [cdn]
    url = bazaar.subutai.io
    sslPort = 443
    ipfsPath = /var/lib/ipfs/node
    templateDownloadUrl = https://ipfs.subutai.io/ipfs/{ID}
    allowInsecure = false

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

	CdnUrl       string
	ManagementIP string
)

func init() {
	log.Level(log.InfoLevel)

	err := gcfg.ReadStringInto(&config, defaultConfig)
	log.Check(log.InfoLevel, "Loading default config ", err)

	confpath := "/etc/subutai/agent.conf"
	log.Check(log.DebugLevel, "Opening Agent default configuration file", gcfg.ReadFileInto(&config, confpath))
	if _, err := os.Stat(confpath); os.IsNotExist(err) {
		log.Check(log.ErrorLevel, "Saving default configuration file", SaveDefaultConfig(confpath))
	}

	log.Check(log.DebugLevel, "Opening Agent configuration file "+confpath, gcfg.ReadFileInto(&config, confpath))

	if config.Agent.GpgUser == "" {
		config.Agent.GpgUser = RhGpgUser
	}

	if config.Agent.GpgHome == "" {
		config.Agent.GpgHome = path.Join(config.Agent.DataPrefix, ".gnupg")
	}
	Agent = config.Agent
	Influxdb = config.Influxdb
	Management = config.Management
	CDN = config.CDN

	CdnUrl = "https://" + path.Join(CDN.URL) + ":" + CDN.SSLport + "/rest/v1/cdn"

}

// InitAgentDebug turns on Debug output for the Subutai Agent.
func InitAgentDebug() {
	if config.Agent.Debug {
		log.Level(log.DebugLevel)
	}
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
