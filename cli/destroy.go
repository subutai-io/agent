package cli

import (
	"strings"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/lib/net/p2p"
	"github.com/subutai-io/agent/lib/template"
	prxy "github.com/subutai-io/agent/refactored/lib/proxy"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/pkg/errors"
	"fmt"
)

// LxcDestroy simply removes every resource associated with a Subutai container or template:
// data, network, configs, etc.
//
// The destroy command always runs each step in "force" mode to provide reliable deletion results;
// even if some instance components were already removed, the destroy command will continue to perform all operations
// once again while ignoring possible underlying errors: i.e. missing configuration files.

func Cleanup(vlan string) {
	list, err := db.FindContainers("", "", vlan)
	if !log.Check(log.WarnLevel, "Reading container metadata from db", err) {
		for _, c := range list {
			err = destroy(c.Name)
			if err != nil {
				log.Error(fmt.Sprintf("Error destroying container %s: %s", c.Name, err.Error()))
			}
		}
		log.Info("Vlan " + vlan + " is destroyed")
	}

	//todo check error here
	cleanupNet(vlan)
}

func LxcDestroy(ids ...string) {
	defer sendHeartbeat()

	if len(ids) == 1 {
		name := ids[0]
		if name == "everything" {
			//destroy all containers
			list, err := db.FindContainers("", "", "")
			if !log.Check(log.ErrorLevel, "Reading container metadata from db", err) {
				for _, cont := range list {
					err = destroy(cont.Name)
					log.Check(log.ErrorLevel, "Destroying container", err)
					if cont.Vlan != "" {
						//todo check error here
						cleanupNet(cont.Vlan)
					}
				}
			}
		} else if strings.HasPrefix(name, "id:") {
			//destroy container by id
			contId := strings.ToUpper(strings.TrimPrefix(name, "id:"))
			for _, c := range container.Containers() {
				if contId == gpg.GetFingerprint(c) {
					err := destroy(c)
					log.Check(log.ErrorLevel, "Destroying container", err)
					break
				}
			}
		} else {
			//destroy container by name
			err := destroy(name)
			log.Check(log.ErrorLevel, "Destroying container", err)
		}

	} else if len(ids) > 1 {
		//destroy a set of containers/templates
		for _, name := range ids {
			err := destroy(name)
			log.Check(log.WarnLevel, "Destroying "+name, err)
		}
	}
}

//destroys template or container by name
func destroy(name string) error {

	if container.IsTemplate(name) {
		err := container.DestroyTemplate(name)

		if err != nil {
			return errors.New(fmt.Sprintf("Error destroying template: %s", err.Error()))
		}

		log.Info("Template " + name + " is destroyed")

	} else {

		c, err := db.FindContainerByName(name)
		log.Check(log.WarnLevel, "Reading container metadata from db", err)

		if c != nil {
			//destroy container that has metadata

			err = removeContainerPortMappings(name)
			if err != nil {
				return errors.New(fmt.Sprintf("Error removing port mapping: %s", err.Error()))
			}

			//todo check error here
			net.DelIface(c.Interface)

			err = container.DestroyContainer(name)
			if err != nil {
				return errors.New(fmt.Sprintf("Error destroying container: %s", err.Error()))
			}

		} else if container.IsContainer(name) {
			//destroy container with missing metadata

			err = container.DestroyContainer(name)

			if err != nil {
				return errors.New(fmt.Sprintf("Error destroying container: %s", err.Error()))
			}

		} else {
			return errors.New(name + " not found")
		}

		if name == container.Management {
			//todo check error here
			template.MngDel()
		}

		log.Info("Container " + name + " is destroyed")
	}

	return nil
}

func cleanupNet(id string) {
	net.DelIface("gw-" + id)
	p2p.RemoveByIface("p2p" + id)
	cleanupNetStat(id)
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

func removeContainerPortMappings(name string) error {
	containerIp := container.GetIp(name)
	servers, err := db.FindProxiedServers("", "")
	if !log.Check(log.WarnLevel, "Fetching port mappings", err) {
		var removedServers []db.ProxiedServer

		for _, server := range servers {
			sock := strings.Split(server.Socket, ":")
			if sock[0] == containerIp {
				err = prxy.RemoveProxiedServer(server.ProxyTag, server.Socket)
				if err != nil {
					log.Error("Error removing server", err)
				}
				removedServers = append(removedServers, server)
			}
		}

		//remove proxies for management container
		if name == container.Management {
			for _, server := range removedServers {
				err = prxy.RemoveProxy(server.ProxyTag)
				if err != nil {
					log.Error("Error removing proxy", err)
				}

			}
		}
	}

	return err
}

type gradedTemplate struct {
	reference string
	grade     int
}

//Prune destroys templates that don't have child containers
//It destroys unused templates by hierarchy, first destroying child templates and then parents
//this is imposed by underlying zfs file system that prohibits destruction of datasets that have child datasets
func Prune() {
	var templatesInUse []string

	//filter out all templates that have child containers
	for _, c := range container.Containers() {
		cont := c

		self := strings.ToLower(strings.TrimSpace(container.GetProperty(cont, "subutai.template")) + ":" +
			strings.TrimSpace(container.GetProperty(cont, "subutai.template.owner")) + ":" +
			strings.TrimSpace(container.GetProperty(cont, "subutai.template.version")))

		parent := strings.ToLower(strings.TrimSpace(container.GetProperty(cont, "subutai.parent")) + ":" +
			strings.TrimSpace(container.GetProperty(cont, "subutai.parent.owner")) + ":" +
			strings.TrimSpace(container.GetProperty(cont, "subutai.parent.version")))

		for self != parent || container.IsContainer(cont) {
			templatesInUse = append(templatesInUse, parent)

			cont = parent

			self = strings.ToLower(strings.TrimSpace(container.GetProperty(cont, "subutai.template")) + ":" +
				strings.TrimSpace(container.GetProperty(cont, "subutai.template.owner")) + ":" +
				strings.TrimSpace(container.GetProperty(cont, "subutai.template.version")))

			parent = strings.ToLower(strings.TrimSpace(container.GetProperty(cont, "subutai.parent")) + ":" +
				strings.TrimSpace(container.GetProperty(cont, "subutai.parent.owner")) + ":" +
				strings.TrimSpace(container.GetProperty(cont, "subutai.parent.version")))
		}

	}

	allTemplates := container.Templates()

	//figure out unused templates
	unusedTemplates := difference(allTemplates, templatesInUse)

	//grade templates by hierarchy
	var gradedTemplates = make(map[string]gradedTemplate)

	maxGrade := 0
	iterations := 0
	for len(gradedTemplates) < len(allTemplates) && iterations < len(allTemplates) {
		iterations++
		for _, t := range allTemplates {
			self := strings.ToLower(strings.TrimSpace(container.GetProperty(t, "subutai.template")) + ":" +
				strings.TrimSpace(container.GetProperty(t, "subutai.template.owner")) + ":" +
				strings.TrimSpace(container.GetProperty(t, "subutai.template.version")))

			parent := strings.ToLower(strings.TrimSpace(container.GetProperty(t, "subutai.parent")) + ":" +
				strings.TrimSpace(container.GetProperty(t, "subutai.parent.owner")) + ":" +
				strings.TrimSpace(container.GetProperty(t, "subutai.parent.version")))

			if self == parent {
				gradedTemplates[self] = gradedTemplate{reference: self, grade: 0}
			} else {
				if gradedParent, ok := gradedTemplates[parent]; ok {
					grade := gradedParent.grade + 1
					gradedTemplates[self] = gradedTemplate{reference: self, grade: grade}
					if grade > maxGrade {
						maxGrade = grade
					}
				}
			}
		}
	}

	//destroy templates starting with highest grade first
	for grade := maxGrade; grade >= 0; grade-- {
		for _, name := range unusedTemplates {
			if t, ok := gradedTemplates[name]; ok && t.grade == grade {
				log.Info("Destroying " + t.reference)
				err := container.DestroyTemplate(t.reference)
				if err != nil {
					log.Error("Error destroying template "+t.reference, err)
				}
			}
		}
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
