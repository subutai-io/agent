// Package config provides configurable variables to other packages, sets logging level, defines global repository accessibility, etc.
package config

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strings"
	"gopkg.in/gcfg.v1"

	"github.com/subutai-io/agent/log"
)

var version = ""

type agentConfig struct {
	Debug       bool
	GpgUser     string
	AppPrefix   string
	LxcPrefix   string
	DataPrefix  string
	GpgPassword string
	GpgHome     string
}
type managementConfig struct {
	Host          string
	Port          string
	Secret        string
	GpgUser       string
	RestPublicKey string
	Fingerprint   string
	Allowinsecure bool
	Experimental  bool
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
	gpgHome =
	debug = true
	appPrefix = /apps/subutai/current/
	dataPrefix = /var/lib/apps/subutai/current/
	lxcPrefix = /var/snap/subutai/common/lxc/
	experimental = false

	[management]
	gpgUser =
	port = 8443
	host =
	secret = secret
	restPublicKey = /rest/v1/security/keyman/getpublickeyring
	allowinsecure = true

    [cdn]
    url = cdn.subutai.io
    sslport = 8338
    allowinsecure = false

	[influxdb]
	server =
	user = root
	pass = root
	db = metrics

	[template]
	version = 5.0.0
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
		config.Template.Branch = strings.TrimPrefix(strings.TrimPrefix(os.Getenv("SNAP_NAME"), "subutai"), "-")
		config.Template.Version = strings.TrimSuffix(version, "-SNAPSHOT")
		config.CDN.URL = config.Template.Branch + "cdn.subutai.io"
	}
	log.Check(log.ErrorLevel, "Saving default configuration file", SaveDefaultConfig(confpath+"agent.gcfg"))
	log.Check(log.DebugLevel, "Opening Agent configuration file "+confpath+"agent.gcfg", gcfg.ReadFileInto(&config, confpath+"agent.gcfg"))

	if config.Agent.GpgUser == "" {
		config.Agent.GpgUser = "rh@subutai.io"
	}

	if config.Agent.GpgHome == "" {
		config.Agent.GpgHome = "/var/snap/" + os.Getenv("SNAP_NAME") + "/current/.gnupg"
	}
	Agent = config.Agent
	Influxdb = config.Influxdb
	Template = config.Template
	Management = config.Management
	CDN = config.CDN

	CDN.Kurjun = "https://" + CDN.URL + ":" + CDN.SSLport + "/kurjun/rest"

}

// InitAgentDebug turns on Debug output for the Subutai Agent.
func InitAgentDebug() {
	if config.Agent.Debug {
		log.Level(log.DebugLevel)
	}
	log.ActivateSyslog("127.0.0.1:1514", "subutai")
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
