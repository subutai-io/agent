package template

import (
	"os/exec"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
)

// MngInit performs initial operations for SS Management deployment
func MngInit(templateRef string) {
	container.Clone(templateRef, "management")

	container.SetContainerUID("management")
	container.SetContainerConf("management", [][]string{
		{"lxc.network.veth.pair", "management"},
	})
	gpg.GenerateKey("management")
	container.SetApt("management")
	container.SetDNS("management")
	container.AddMetadata("management", map[string]string{"ip": "10.10.10.1"})
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
