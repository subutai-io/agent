package cli

import (
	"os/exec"
	"strings"

	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
)

type VxlanTunnel struct {
	Name     string
	RemoteIp string
	Vlan     string
	Vni      string
}

func AddVxlanTunnel(name, remoteip, vlan, vni string) {
	tunnelCreate(name, remoteip, vlan, vni)
}

func DelVxlanTunnel(name string) {
	net.DelIface(name)
}

// tunnelCreate creates VXLAN tunnel
func tunnelCreate(tunnel, addr, vlan, vni string) {
	log.Check(log.WarnLevel, "Creating bridge ", exec.Command("ovs-vsctl", "--may-exist", "add-br", "gw-"+vlan).Run())

	log.Check(log.FatalLevel, "Creating tunnel port",
		exec.Command("ovs-vsctl", "--may-exist", "add-port", "gw-"+vlan, tunnel, "--", "set", "interface", tunnel, "type=vxlan",
			"options:stp_enable=true", "options:key="+vni, "options:remote_ip="+addr).Run())

	log.Check(log.FatalLevel, "MakeVNIMap set port: ", exec.Command("ovs-vsctl", "--if-exists", "set", "port", tunnel, "tag="+vlan).Run())
}

//tunnelList prints a list of existing VXLAN tunnels
func GetVxlanTunnels() []VxlanTunnel {
	var res = []VxlanTunnel{}

	ret, err := exec.Command("ovs-vsctl", "show").CombinedOutput()
	log.Check(log.FatalLevel, "Getting OVS interfaces list", err)
	ports := strings.Split(string(ret), "\n")

	for k, port := range ports {
		if strings.Contains(port, "remote_ip") {
			tunnel := strings.Trim(strings.Trim(ports[k-2], "Interface "), "\"")
			vlan := strings.TrimLeft(ports[k-3], "tag: ")
			addr := strings.Fields(port)
			vni := strings.Trim(strings.Trim(addr[1], "{key="), "\",")
			ip := strings.Trim(strings.Trim(addr[2], "remote_ip="), "\",")
			res = append(res, VxlanTunnel{Name: tunnel, RemoteIp: ip, Vlan: vlan, Vni: vni})
		}
	}

	return res
}
