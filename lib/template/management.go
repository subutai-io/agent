package template

import (
	"os/exec"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
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
	gpg.GenerateKey("management")
	container.Start("management")

	//TODO move mapping functions from cli package and get rid of exec
	log.Check(log.WarnLevel, "Exposing port 8443",
		exec.Command("subutai", "map", "tcp", "-i", "10.10.10.1:8443", "-e", "8443").Run())
	log.Check(log.WarnLevel, "Exposing port 8444",
		exec.Command("subutai", "map", "tcp", "-i", "10.10.10.1:8444", "-e", "8444").Run())
	log.Check(log.WarnLevel, "Exposing port 8086",
		exec.Command("subutai", "map", "tcp", "-i", "10.10.10.1:8086", "-e", "8086").Run())

	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	log.Check(log.WarnLevel, "Writing container data to database", bolt.ContainerAdd("management", map[string]string{"ip": "10.10.10.1"}))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	log.Info("********************")
	log.Info("Subutai Management UI will be shortly available at https://" + net.GetIp() + ":8443")
	log.Info("login: admin")
	log.Info("password: secret")
	log.Info("********************")
}

// MngDel removes Management network interfaces, resets dhcp client
func MngDel() {
	exec.Command("ovs-vsctl", "del-port", "wan", "management").Run()
	exec.Command("ovs-vsctl", "del-port", "wan", "mng-gw").Run()
}
