package template

import (
	"os/exec"

	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/db"
)

// MngInit performs initial operations for SS Management deployment
func MngInit(templateRef string) {
	container.Clone(templateRef, container.Management)

	container.SetContainerUID(container.Management)
	container.SetContainerConf(container.Management, [][]string{
		{"lxc.network.veth.pair", container.Management},
	})
	gpg.GenerateKey(container.Management)
	container.SetDNS(container.Management)
	container.AddMetadata(container.Management, map[string]string{"ip": "10.10.10.1"})
	container.Start(container.Management)

	//TODO move mapping functions from cli package and get rid of exec
	//TODO use new subutai prxy binding
	log.Check(log.WarnLevel, "Exposing port 8443",
		exec.Command("subutai", "map", "add", "-p", "tcp", "-i", "10.10.10.1:8443", "-e", "8443").Run())
	log.Check(log.WarnLevel, "Exposing port 8444",
		exec.Command("subutai", "map", "add", "-p", "tcp", "-i", "10.10.10.1:8444", "-e", "8444").Run())
	log.Check(log.WarnLevel, "Exposing port 8086",
		exec.Command("subutai", "map", "add", "-p", "tcp", "-i", "10.10.10.1:8086", "-e", "8086").Run())

	log.Check(log.ErrorLevel, "Writing container data to database", db.INSTANCE.SaveContainer(container.Management, map[string]string{"ip": "10.10.10.1"}))

	log.Info("********************")
	log.Info("Subutai Management UI will be shortly available at https://" + net.GetIp() + ":8443")
	log.Info("login: admin")
	log.Info("password: secret")
	log.Info("********************")
}

// MngDel removes Management network interfaces, resets dhcp client
func MngDel() {
	exec.Command("ovs-vsctl", "del-port", "wan", container.Management).Run()
	exec.Command("ovs-vsctl", "del-port", "wan", "mng-gw").Run()
}
