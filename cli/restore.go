package cli

import (
	"strings"
	"github.com/subutai-io/agent/lib/container"
	"github.com/nightlyone/lockfile"
	"time"
	"github.com/subutai-io/agent/lib/common"
	"github.com/subutai-io/agent/lib/fs"
	"path"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/gpg"
	"fmt"
	"reflect"
	"sort"
	"github.com/subutai-io/agent/lib/net"
	"strconv"
)

//todo remove code duplicates from LxcClone and RestoreContainer by moving common part to lib

func RestoreContainer(containerName, envID, addr, consoleSecret string) {

	containerName = strings.TrimSpace(containerName)

	checkArgument(containerName != "", "Invalid container name")

	checkState(container.IsContainer(containerName), "Container %s not found", containerName)

	configFilePath := path.Join(config.Agent.LxcPrefix, containerName, "config")

	checkState(fs.FileExists(configFilePath), "Config file not found")

	//synchronize
	var lock lockfile.Lockfile
	var err error
	for lock, err = common.LockFile("", "clone"); err != nil; lock, err = common.LockFile("", "clone") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()
	//<<<synchronize

	defer sendHeartbeat()

	parentParts := []string{
		container.GetProperty(containerName, "subutai.template"),
		container.GetProperty(containerName, "subutai.template.owner"),
		container.GetProperty(containerName, "subutai.template.version"),
	}

	parent := strings.Join(parentParts, ":")

	t := getTemplateInfo(parent)

	log.Debug("Parent template is " + t.Name + "@" + t.Owner + ":" + t.Version)

	cont := &db.Container{}
	cont.Name = containerName
	cont.Template = t.Name
	cont.TemplateOwner = t.Owner
	cont.TemplateVersion = t.Version
	cont.TemplateId = t.Id

	mac, err := container.Mac()
	log.Check(log.ErrorLevel, "Generating mac address", err)

	mtu, err := net.GetP2pMtu()
	log.Check(log.ErrorLevel, "Obtaining MTU", err)

	err = container.SetContainerConf(containerName, [][]string{
		{"lxc.network.hwaddr", mac},
		{"lxc.network.veth.pair", strings.Replace(mac, ":", "", -1)},
		{"lxc.network.mtu", strconv.Itoa(mtu)},
		{"subutai.parent", parentParts[0]},
		{"subutai.parent.owner", parentParts[1]},
		{"subutai.parent.version", parentParts[2]},
		{"lxc.rootfs", path.Join(config.Agent.LxcPrefix, containerName, "rootfs")},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, containerName, "home") + " home none bind,rw 0 0"},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, containerName, "opt") + " opt none bind,rw 0 0"},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, containerName, "var") + " var none bind,rw 0 0"},
		{"lxc.rootfs.backend", "zfs"}, //must be in template
		{"lxc.utsname", containerName},
		{"lxc.cgroup.memory.limit_in_bytes"},
		{"lxc.cgroup.cpu.cfs_quota_us"},
	})

	gpg.GenerateKey(containerName)
	if len(consoleSecret) != 0 {
		gpg.ExchangeAndEncrypt(containerName, consoleSecret)
	}

	if len(envID) != 0 {
		cont.EnvironmentId = envID
	}

	if ip := strings.Fields(addr); len(ip) > 1 {

		cont.Ip = strings.Split(ip[0], "/")[0]
		cont.Gateway = getOrGenerateGateway(addr)
		cont.Vlan = ip[1]

		container.SetContainerConf(containerName, [][]string{
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

		container.SetContainerConf(containerName, [][]string{
			{"lxc.network.flags", "up"},
			{"lxc.network.ipv4", fmt.Sprintf("%s/24", cont.Ip)},
			{"lxc.network.ipv4.gateway", cont.Gateway},
			{"#vlan_id"},
		})
	}

	//changing from dhcp to manual
	container.SetStaticNet(containerName)

	cont.Uid, _ = container.SetContainerUID(containerName)

	//Need to change it in parent templates
	container.SetDNS(containerName)
	//add subutai.template.owner & subutai.template.version
	container.CopyParentReference(containerName, t.Owner, t.Version)

	//Security matters workaround. Need to change it in parent templates
	container.DisableSSHPwd(containerName)

	cont.Interface = container.GetProperty(containerName, "lxc.network.veth.pair")

	log.Check(log.ErrorLevel, "Writing container metadata to database", db.SaveContainer(cont))

	LxcStart(containerName)

	log.Info(containerName + " with ID " + gpg.GetFingerprint(containerName) + " successfully restored")

}
