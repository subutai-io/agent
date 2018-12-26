package net

import (
	"strings"
	"github.com/subutai-io/agent/log"
	"os/exec"
	exc "github.com/subutai-io/agent/lib/exec"
	"net"
	"strconv"
	"bufio"
	"bytes"
	"github.com/pkg/errors"
	"fmt"
)
//todo return errors , dont use log.Error/Fatal

func DelIface(iface string) {
	log.Debug("Removing interface " + iface)
	exec.Command("ovs-vsctl", "--if-exists", "del-br", iface).Run()
	exec.Command("ovs-vsctl", "--if-exists", "del-port", iface).Run()
	exec.Command("ip", "set", "dev", iface, "down").Run()
}

func IsValidSocket(socket string) bool {
	if addr := strings.Split(socket, ":"); len(addr) == 2 {
		if _, err := net.ResolveIPAddr("ip4", addr[0]); err == nil {
			if port, err := strconv.Atoi(addr[1]); err == nil && port < 65536 {
				return true
			}
		}
	}
	return false
}

// RemoveP2pIface deletes P2P interface from the Resource Host.
func RemoveP2pIface(name string) {
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

func GetP2pMtu() (int, error){
	out, err := exec.Command("p2p", "show", "--mtu").CombinedOutput()
	output := strings.TrimSpace(string(out))
	if log.Check(log.DebugLevel, "Getting p2p mtu: "+output, err) {
		return -1, errors.New(fmt.Sprintf("Error getting p2p mtu: %s", err.Error()))
	}


	mtu, err := strconv.Atoi(output)
	if log.Check(log.DebugLevel, "Parsing p2p mtu: "+output, err) {
		return -1, errors.New(fmt.Sprintf("Error parsing p2p mtu: %s", err.Error()))
	}

	return mtu - 50, nil
}

// RateLimit sets throughput limits for container's network interfaces if "quota" is specified
func RateLimit(nic string, rate string) string {
	if rate != "" {
		burst, _ := strconv.Atoi(rate)
		burst = burst / 10

		exec.Command("ovs-vsctl", "set", "interface", nic,
			"ingress_policing_rate="+rate).Run()

		exec.Command("ovs-vsctl", "set", "interface", nic,
			"ingress_policing_burst="+strconv.Itoa(burst)).Run()
	}

	out, _ := exec.Command("ovs-vsctl", "list", "interface", nic).Output()

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) > 0 {
			if line[0] == "ingress_policing_rate:" {
				return line[1]
			}
		}
	}
	return ""
}

// GetIp returns IP address that should be used for host access
func GetIp() string {

	out, err := exc.ExecuteWithBash("ip route get 1.1.1.1 | grep -oP 'src \\K\\S+'")

	ip := strings.TrimSpace(out)
	if log.Check(log.WarnLevel, "Getting RH IP "+ip, err) {
		return ""
	}

	return ip
}
