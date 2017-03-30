package cli

import (
	"strings"

	"github.com/influxdata/influxdb/client/v2"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/lib/net/p2p"
	"github.com/subutai-io/agent/lib/template"
	"github.com/subutai-io/agent/log"
)

// LxcDestroy simply removes every resource associated with a Subutai container or template:
// data, network, configs, etc.
//
// The destroy command always runs each step in "force" mode to provide reliable deletion results;
// even if some instance components were already removed, the destroy command will continue to perform all operations
// once again while ignoring possible underlying errors: i.e. missing configuration files.
func LxcDestroy(id string, vlan bool) {
	var v string
	var msg string
	if len(id) == 0 {
		log.Error("Please specify container/template name or vlan id")
	}

	if strings.HasPrefix(id, "id:") {
		for _, c := range container.Containers() {
			if strings.ToUpper(strings.TrimPrefix(id, "id:")) == gpg.GetFingerprint(c) {
				LxcDestroy(c, false)
				return
			}
			msg = id + " not found. Please check if a container name is correct."
		}
	} else if vlan {
		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		list := bolt.ContainerByKey("vlan", id)
		log.Check(log.WarnLevel, "Closing database", bolt.Close())
		for _, c := range list {
			msg = "Vlan " + id + " is destroyed"
			LxcDestroy(c, false)
		}
		cleanupNet(id)
	} else {
		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		c := bolt.ContainerByName(id)
		log.Check(log.WarnLevel, "Closing database", bolt.Close())

		if len(c) != 0 {
			msg = id + " is destroyed"
		}

		if ip, ok := c["ip"]; ok {
			cleanupPortMap(c["ip"])
			if vlan, ok := c["vlan"]; ok {
				ProxyDel(vlan, ip, false)
			}
		}
		net.DelIface(c["interface"])
		container.Destroy(id)
	}

	if id == "everything" {
		for _, c := range container.Containers() {
			if vlan := container.GetConfigItem(config.Agent.LxcPrefix+c+"/config", "#vlan_id"); len(vlan) != 0 {
				if vlan != v {
					LxcDestroy(vlan, true)
					cleanupNet(vlan)
					v = vlan
				}
			} else {
				LxcDestroy(c, false)
			}
		}
		msg = id + " is destroyed"
	}

	if id == "management" || id == "everything" {
		template.MngDel()
	}
	if len(msg) == 0 {
		msg = id + " not found. Please check if a container name is correct."
	}
	log.Info(msg)
}

func cleanupNet(id string) {
	net.DelIface("gw-" + id)
	p2p.RemoveByIface("p2p" + id)
	cleanupNetStat(id)
	ProxyDel(id, "", true)
}

// cleanupNetStat drops data from database about network trafic for specified VLAN
func cleanupNetStat(vlan string) {
	c, _ := client.NewHTTPClient(client.HTTPConfig{
		Addr:               "https://" + config.Influxdb.Server + ":8086",
		Username:           config.Influxdb.User,
		Password:           config.Influxdb.Pass,
		InsecureSkipVerify: true,
	})
	queryInfluxDB(c, `drop series from host_net where iface = 'p2p`+vlan+`'`)
	queryInfluxDB(c, `drop series from host_net where iface = 'gw-`+vlan+`'`)
}

func cleanupPortMap(ip string) {
	list := make(map[string][]string)
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database to list portmap", err)
	for _, proto := range []string{"tcp", "udp", "http"} {
		list[proto] = bolt.ExtPorts(proto, ip)
	}
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for proto, ports := range list {
		for _, port := range ports {
			log.Debug("Removing map: " + proto + ", " + ip + ", " + port)
			mapRemove(proto, ip, port)
		}
	}
	restart()
}
