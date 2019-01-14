package cli

import (
	"net"
	"strings"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/util"
	"regexp"
	"fmt"
	"reflect"
	"sort"
	"github.com/nightlyone/lockfile"
	"time"
	"github.com/subutai-io/agent/lib/common"
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

	util.VerifyLxcName(child)

	if container.LxcInstanceExists(child) {
		log.Error("Container " + child + " already exists")
	}

	//synchronize
	var lock lockfile.Lockfile
	var err error
	for lock, err = common.LockFile("", "clone"); err != nil; lock, err = common.LockFile("", "clone") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()
	//<<<synchronize

	defer sendHeartbeat()

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
		gpg.ExchangeAndEncrypt(child, consoleSecret)
	}

	if len(envID) != 0 {
		cont.EnvironmentId = envID
	}

	if ip := strings.Fields(addr); len(ip) > 1 {

		cont.Ip = strings.Split(ip[0], "/")[0]
		cont.Gateway = getOrGenerateGateway(addr)
		cont.Vlan = ip[1]

		container.SetContainerConf(child, [][]string{
			{"lxc.network.flags", "up"},
			{"lxc.network.ipv4", fmt.Sprintf("%s/24", cont.Ip)},
			{"lxc.network.ipv4.gateway", cont.Gateway},
			{"#vlan_id", cont.Vlan},
		})
	} else {
		//determine next free IP
		freeIPs := make(map[string]bool)
		for i := 100; i < 200; i++ {
			freeIPs[fmt.Sprintf("10.10.10.%d", i)] = true
		}

		for _, cont := range container.Containers() {
			ip := container.GetIp(cont)
			delete(freeIPs, ip)
		}

		if len(freeIPs) == 0 {
			log.Error("There is no free IP in range 10.10.10.1xx left")
		}

		//sort IPs
		keys := reflect.ValueOf(freeIPs).MapKeys()
		sort.Slice(keys[:], func(i, j int) bool {
			return keys[i].String() < keys[j].String()
		})
		//use first free ip
		cont.Ip = keys[0].String()
		cont.Gateway = "10.10.10.254"

		container.SetContainerConf(child, [][]string{
			{"lxc.network.flags", "up"},
			{"lxc.network.ipv4", fmt.Sprintf("%s/24", cont.Ip)},
			{"lxc.network.ipv4.gateway", cont.Gateway},
		})

	}
	//changing from dhcp to manual
	container.SetStaticNet(child)

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

// getOrGenerateGateway adds network related configuration values to container config file
func getOrGenerateGateway(addr string) string {
	ipvlan := strings.Fields(addr)
	gateway := getEnvGw(ipvlan[1])
	if len(gateway) == 0 {
		ipaddr, network, _ := net.ParseCIDR(ipvlan[0])
		gw := []byte(network.IP)
		ip := []byte(ipaddr.To4())
		gw[3] = gw[3] + 255 - ip[3]
		gateway = net.IP(gw).String()
	}

	return gateway
}

func getEnvGw(vlan string) (gw string) {

	list, _ := db.FindContainers("", "", vlan)

	if len(list) > 0 {
		gw = list[0].Gateway
	}

	return
}
