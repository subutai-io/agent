package cli

import (
	"strings"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/lib/net/p2p"
	"github.com/subutai-io/agent/lib/template"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/lib/fs"
	"runtime"
	"github.com/subutai-io/agent/config"
)

// LxcDestroy simply removes every resource associated with a Subutai container or template:
// data, network, configs, etc.
//
// The destroy command always runs each step in "force" mode to provide reliable deletion results;
// even if some instance components were already removed, the destroy command will continue to perform all operations
// once again while ignoring possible underlying errors: i.e. missing configuration files.
func LxcDestroy(id string, vlan bool) {
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
	} else if id != "everything" {
		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		log.Debug("Obtaining container by name")
		c := bolt.ContainerByName(id)
		log.Check(log.WarnLevel, "Closing database", bolt.Close())

		msg = id + " is destroyed"

		if len(c) != 0 {

			if ip, ok := c["ip"]; ok {
				if vlan, ok := c["vlan"]; ok {
					ProxyDel(vlan, ip, false)
				}
			}

			removePortMap(id)

			net.DelIface(c["interface"])

			log.Check(log.ErrorLevel, "Destroying container", container.DestroyContainer(id))

			if container.IsTemplate(id) {
				container.DeleteTemplateInfoFromCache(id)
			}

		} else if container.IsTemplate(id) {

			container.DestroyTemplate(id)
		} else {

			err = container.DestroyContainer(id)

			log.Check(log.ErrorLevel, "Destroying container", err)
		}
	}

	if id == "everything" {
		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		list := bolt.ContainerList()
		log.Check(log.WarnLevel, "Closing database", bolt.Close())

		for _, name := range list {
			bolt, err := db.New()
			log.Check(log.WarnLevel, "Opening database", err)
			c := bolt.ContainerByName(name)
			log.Check(log.WarnLevel, "Closing database", bolt.Close())

			LxcDestroy(name, false)
			if v, ok := c["vlan"]; ok {
				cleanupNet(v)
			}
		}
		msg = id + " is destroyed"
	}

	if id == "management" {
		template.MngDel()
	}

	if len(msg) == 0 {
		msg = id + " not found. Please check if the name is correct"
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
	c, err := utils.InfluxDbClient()
	if err == nil {
		defer c.Close()
	}
	queryInfluxDB(c, `drop series from host_net where iface = 'p2p`+vlan+`'`)
	queryInfluxDB(c, `drop series from host_net where iface = 'gw-`+vlan+`'`)
}

func removePortMap(name string) {
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	log.Debug("Obtaining container port mappings")
	list := bolt.GetContainerMapping(name)
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for _, v := range list {
		MapPort(v["protocol"], v["internal"], v["external"], "", v["domain"], "", false, true, false)
	}
}

func Prune(what string) {
	if what == "archives" {

		//remove all template archives
		wildcardTemplateName := config.Agent.LxcPrefix + "tmpdir/*" +
			"-subutai-template_*_" + strings.ToLower(runtime.GOARCH) + ".tar.gz"

		fs.DeleteFilesWildcard(wildcardTemplateName)

	} else if what == "templates" {

		var templatesInUse []string

		//collect all used templates
		for _, c := range container.Containers() {
			parent := strings.TrimSpace(container.GetParent(c))
			for parent != c && parent != "" {
				templatesInUse = append(templatesInUse, parent)
				c = parent
				parent = strings.TrimSpace(container.GetParent(c))
			}
		}

		//figure out unused templates
		unusedTemplates := difference(container.Templates(), templatesInUse)

		//remove unused templates
		for _, t := range unusedTemplates {
			container.DestroyTemplate(t)
		}

	} else {

		log.Error("Only archives/templates can be pruned")
	}
}

func difference(a, b []string) []string {
	mb := map[string]bool{}
	for _, x := range b {
		mb[x] = true
	}
	var ab []string
	for _, x := range a {
		if _, ok := mb[x]; !ok {
			ab = append(ab, x)
		}
	}
	return ab
}
