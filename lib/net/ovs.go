// net package purposed to work with Subutai network components and network-related container configuration
package net

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/subutai-io/agent/log"
)

// RateLimit sets throughput limits for container's network interfaces if "quota" is specified
func RateLimit(nic string, rate ...string) string {
	if rate[0] != "" {
		burst, _ := strconv.Atoi(rate[0])
		burst = burst / 10

		exec.Command("ovs-vsctl", "set", "interface", nic,
			"ingress_policing_rate="+rate[0]).Run()

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
	var iface string
	out, err := exec.Command("route").Output()
	if !log.Check(log.DebugLevel, "Running route command", err) {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "default") {
				line := strings.Fields(scanner.Text())
				iface = line[len(line)-1]
			}
		}
	}

	if len(iface) != 0 {
		if nic, err := net.InterfaceByName(iface); err == nil {
			if addrs, err := nic.Addrs(); err == nil && len(addrs) > 0 {
				if ipnet, ok := addrs[0].(*net.IPNet); ok {
					if ipnet.IP.To4() != nil {
						return ipnet.IP.String()
					}
				}
			}
		}
	}

	return "null"
}
