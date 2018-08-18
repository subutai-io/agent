// net package purposed to work with Subutai network components and network-related container configuration
package net

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	exc "github.com/subutai-io/agent/lib/exec"
	"github.com/subutai-io/agent/log"
)

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

	if log.Check(log.WarnLevel, "Getting RH ip "+out, err) {
		return ""
	}

	return strings.TrimSpace(out)
}
