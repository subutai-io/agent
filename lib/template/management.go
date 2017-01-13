package template

import (
	"os/exec"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
)

// MngInit performs initial operations for SS Management deployment
func MngInit() {
	fs.ReadOnly("management", false)
	container.SetContainerUID("management")
	container.SetContainerConf("management", [][]string{
		{"lxc.network.hwaddr", Mac()},
		{"lxc.network.veth.pair", "management"},
		{"lxc.network.script.up", config.Agent.AppPrefix + "bin/create_ovs_interface"},
		{"lxc.network.link", ""},
		{"lxc.mount", config.Agent.LxcPrefix + "management/fstab"},
		{"lxc.rootfs", config.Agent.LxcPrefix + "management/rootfs"},
		{"lxc.rootfs.mount", config.Agent.LxcPrefix + "management/rootfs"},
		// TODO following lines kept for back compatibility with old templates, should be deleted when all templates will be replaced.
		{"lxc.mount.entry", config.Agent.LxcPrefix + "management/home home none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + "management/opt opt none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + "management/var var none bind,rw 0 0"},
	})
	container.SetApt("management")
	container.SetContainerUID("management")
	gpg.GenerateKey("management")
	container.Start("management")

	log.Info("********************")
	log.Info("Subutai Management UI will be shortly available at https://" + net.GetIp() + ":8443")
	log.Info("login: admin")
	log.Info("password: secret")
	log.Info("********************")
}

// MngStop drops port forwarding rules needed by Management container
func MngStop() {
	for _, iface := range []string{"wan", "eth1", "eth2"} {
		for _, port := range []string{"8443", "8444"} {
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p",
				"tcp", "--dport", port, "-j", "DNAT", "--to-destination", "10.10.10.1:"+port).Run()
		}
	}
}

// MngDel removes Management network interfaces, resets dhcp client
func MngDel() {
	exec.Command("ovs-vsctl", "del-port", "wan", "management").Run()
	exec.Command("ovs-vsctl", "del-port", "wan", "mng-gw").Run()
}
