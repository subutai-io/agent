package cli

import (
	"strings"

	"github.com/influxdata/influxdb/client/v2"

	"github.com/subutai-io/agent/config"
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

	if len(id) == 0 {
		log.Error("Please specify container/template name or vlan id")
	}

	if strings.HasPrefix(id, "id:") {
		for _, c := range container.Containers() {
			if strings.ToUpper(strings.TrimPrefix(id, "id:")) == gpg.GetFingerprint(c) {
				container.Destroy(c)
				break
			}
		}
	}

	if vlan {
		for _, c := range container.Containers() {
			if container.GetConfigItem(config.Agent.LxcPrefix+c+"/config", "#vlan_id") == id {
				LxcDestroy(c, false)
			}
		}
		cleanupNet(id)
	} else {
		net.DelIface(container.GetConfigItem(config.Agent.LxcPrefix+id+"/config", "lxc.network.veth.pair"))
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
	}

	if id == "management" || id == "everything" {
		template.MngStop()
		template.MngDel()
	}
	log.Info(id + " is destroyed")
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
