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
	log.Check(log.WarnLevel, "Setting up proxy for port 8443",
		exec.Command("subutai", "prxy", "create", "-t", "management-8443", "-p", "tcp", "-e", "8443").Run())
	log.Check(log.WarnLevel, "Redirecting port 8443 to management container",
		exec.Command("subutai", "prxy", "srv", "add", "-t", "management-8443", "-s", "10.10.10.1:8443").Run())
	log.Check(log.WarnLevel, "Setting up proxy for port 8444",
		exec.Command("subutai", "prxy", "create", "-t", "management-8444", "-p", "tcp", "-e", "8444").Run())
	log.Check(log.WarnLevel, "Redirecting port 8444 to management container",
		exec.Command("subutai", "prxy", "srv", "add", "-t", "management-8444", "-s", "10.10.10.1:8444").Run())
	log.Check(log.WarnLevel, "Setting up proxy for port 8086",
		exec.Command("subutai", "prxy", "create", "-t", "management-8086", "-p", "tcp", "-e", "8086").Run())
	log.Check(log.WarnLevel, "Redirecting port 8086 to management container",
		exec.Command("subutai", "prxy", "srv", "add", "-t", "management-8086", "-s", "10.10.10.1:8086").Run())

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
