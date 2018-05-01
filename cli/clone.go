package cli

import (
	"net"
	"strings"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"regexp"
)

var (
	templateNameNOwnerNVersionRx = regexp.MustCompile(`^(?P<name>[a-zA-Z0-9._-]+)[@:](?P<owner>[a-zA-Z0-9._-]+):(?P<version>\d+\.\d+\.\d+)$`)
	templateNameNOwnerRx         = regexp.MustCompile(`^(?P<name>[a-zA-Z0-9._-]+)[@:](?P<owner>[a-zA-Z0-9._-]+)$`)
	templateNameRx               = regexp.MustCompile(`^(?P<name>[a-zA-Z0-9._-]+)$`)
)
// LxcClone function creates new `child` container from a Subutai `parent` template.
//
// If the specified template argument is not deployed in system, Subutai first tries to import it, and if import succeeds, it then continues to clone from the imported template image.
// By default, clone will use the NAT-ed network interface with IP address received from the Subutai DHCP server, but this behavior can be changed with command options described below.
//
// If `-i` option is defined, separate bridge interface will be created in specified VLAN and new container will receive static IP address.
// Option `-e` writes the environment ID string inside new container.
// Option `-t` is intended to check the origin of new container creation request during environment build.
// This is one of the security checks which makes sure that each container creation request is authorized by registered user.
//
// The clone options are not intended for manual use: unless you're confident about what you're doing. Use default clone format without additional options to create Subutai containers.
func LxcClone(parent, child, envID, addr, consoleSecret, cdnToken string) {
	child = utils.CleanTemplateName(child)

	if container.LxcInstanceExists(child) {
		log.Error("Container " + child + " already exists")
	}

	t := getTemplateInfo(parent, cdnToken)

	log.Debug("Parent template is " + t.Name + "@" + t.Owner[0] + ":" + t.Version)

	meta := make(map[string]string)
	meta["parent"] = t.Name
	meta["parent.owner"] = t.Owner[0]
	meta["parent.version"] = t.Version
	meta["parent.id"] = t.Id

	fullRef := strings.Join([]string{t.Name, t.Owner[0], t.Version}, ":")

	if !container.IsTemplate(fullRef) {
		LxcImport("id:"+t.Id, cdnToken, false)
	}

	log.Check(log.ErrorLevel, "Cloning the container", container.Clone(fullRef, child))

	gpg.GenerateKey(child)
	if len(consoleSecret) != 0 {
		gpg.ExchageAndEncrypt(child, consoleSecret)
	}

	if len(envID) != 0 {
		meta["environment"] = envID
	}

	if ip := strings.Fields(addr); len(ip) > 1 {
		meta["gw"] = addNetConf(child, addr)
		meta["ip"] = strings.Split(ip[0], "/")[0]
		meta["vlan"] = ip[1]
	}

	meta["uid"], _ = container.SetContainerUID(child)

	//Need to change it in parent templates
	container.SetApt(child)
	container.SetDNS(child)
	//add subutai.template.owner & subutai.template.version
	container.CopyParentReference(child, t.Owner[0], t.Version)

	//Security matters workaround. Need to change it in parent templates
	container.DisableSSHPwd(child)

	LxcStart(child)

	meta["interface"] = container.GetConfigItem(config.Agent.LxcPrefix+child+"/config", "lxc.network.veth.pair")

	bolt, err := db.New()
	if ! log.Check(log.WarnLevel, "Opening database", err) {
		defer bolt.Close()
		log.Check(log.WarnLevel, "Writing container data to database", bolt.ContainerAdd(child, meta))
	}

	log.Info(child + " with ID " + gpg.GetFingerprint(child) + " successfully cloned")
}

// addNetConf adds network related configuration values to container config file
func addNetConf(name, addr string) string {
	ipvlan := strings.Fields(addr)
	gateway := getEnvGw(ipvlan[1])
	if len(gateway) == 0 {
		ipaddr, network, _ := net.ParseCIDR(ipvlan[0])
		gw := []byte(network.IP)
		ip := []byte(ipaddr.To4())
		gw[3] = gw[3] + 255 - ip[3]
		gateway = net.IP(gw).String()
	}

	container.SetContainerConf(name, [][]string{
		{"lxc.network.flags", "up"},
		{"lxc.network.ipv4", ipvlan[0]},
		{"lxc.network.ipv4.gateway", gateway},
		{"#vlan_id", ipvlan[1]},
	})
	container.SetStaticNet(name)

	return gateway
}

func getEnvGw(vlan string) (gw string) {

	bolt, err := db.New()
	if err == nil {
		defer bolt.Close()
	} else {
		log.Warn("Failed to open db", err)
		return
	}

	list := bolt.ContainerByKey("vlan", vlan)

	if len(list) > 0 {
		meta := bolt.ContainerByName(list[0])
		gw = meta["gw"]
	}

	return
}
