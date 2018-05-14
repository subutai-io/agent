package net

import (
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/subutai-io/agent/log"
)

// DelIface removes OVS bridges and ports by name, brings system interface down
func DelIface(iface string) {
	log.Debug("Removing interface " + iface)
	exec.Command("ovs-vsctl", "--if-exists", "del-br", iface).Run()
	exec.Command("ovs-vsctl", "--if-exists", "del-port", iface).Run()
	exec.Command("ip", "set", "dev", iface, "down").Run()
}

func ValidSocket(socket string) bool {
	if addr := strings.Split(socket, ":"); len(addr) == 2 {
		if _, err := net.ResolveIPAddr("ip4", addr[0]); err == nil {
			if port, err := strconv.Atoi(addr[1]); err == nil && port < 65536 {
				return true
			}
		}
	}
	return false
}
