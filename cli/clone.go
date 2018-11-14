package cli

import (
	"net"
	"strings"

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
func LxcClone(parent, child, envID, addr, consoleSecret string) {
	utils.VerifyLxcName(child)

	if container.LxcInstanceExists(child) {
		log.Error("Container " + child + " already exists")
	}

	t := getTemplateInfo(parent)

	log.Debug("Parent template is " + t.Name + "@" + t.Owner + ":" + t.Version)

	cont := &db.Container{}
	cont.Name = child
	cont.Template = t.Name
	cont.TemplateOwner = t.Owner
	cont.TemplateVersion = t.Version
	cont.TemplateId = t.Id

	fullRef := strings.Join([]string{t.Name, t.Owner, t.Version}, ":")

	if !container.IsTemplate(fullRef) {
		LxcImport("id:"+t.Id, "")
	}

	log.Check(log.ErrorLevel, "Cloning the container", container.Clone(fullRef, child))

	gpg.GenerateKey(child)
	if len(consoleSecret) != 0 {
		gpg.ExchageAndEncrypt(child, consoleSecret)
	}

	if len(envID) != 0 {
		cont.EnvironmentId = envID
	}

	if ip := strings.Fields(addr); len(ip) > 1 {
		cont.Gateway = addNetConf(child, addr)
		cont.Ip = strings.Split(ip[0], "/")[0]
		cont.Vlan = ip[1]
	}

	cont.Uid, _ = container.SetContainerUID(child)

	//Need to change it in parent templates
	container.SetDNS(child)
	//add subutai.template.owner & subutai.template.version
	container.CopyParentReference(child, t.Owner, t.Version)

	//Security matters workaround. Need to change it in parent templates
	container.DisableSSHPwd(child)

	LxcStart(child)

	cont.Interface = container.GetProperty(child, "lxc.network.veth.pair")

	log.Check(log.ErrorLevel, "Writing container metadata to database", db.SaveContainer(cont))

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

	list, _ := db.FindContainers("", "", vlan)

	if len(list) > 0 {
		gw = list[0].Gateway
	}

	return
}
