// p2p package provides control interface for p2p service
package p2p

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"

	"github.com/subutai-io/agent/log"
)

// RemoveByIface deletes P2P interface from the Resource Host.
func RemoveByIface(name string) {
	mac := ""
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Name == name {
			mac = iface.HardwareAddr.String()
		}
	}
	out, _ := exec.Command("p2p", "show").Output()
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) > 1 && line[0] == mac {
			log.Check(log.WarnLevel, "Removing p2p interface", exec.Command("p2p", "stop", "-hash", line[2]).Run())

		}
	}
	log.Check(log.WarnLevel, "Removing p2p interface from registered list", exec.Command("p2p", "stop", "--dev", name).Run())
	log.Check(log.WarnLevel, "Removing p2p interface from system", exec.Command("ip", "link", "delete", name).Run())
	log.Check(log.WarnLevel, "Disabling p2p link", exec.Command("ip", "set", "dev", name, "down").Run())
	iptablesCleanUp(name)
}

// iptablesCleanUp removes Iptables rules applied for passed interface
func iptablesCleanUp(name string) {
	out, _ := exec.Command("iptables-save").Output()
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, name) {
			args := strings.Fields(line)
			args[0] = "-D"
			exec.Command("iptables", append([]string{"-t", "nat"}, args...)...).Run()
		}
	}
}
