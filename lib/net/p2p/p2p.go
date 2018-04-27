// p2p package provides control interface for p2p service
package p2p

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/subutai-io/agent/log"
)

// Create adds new P2P interface to the Resource Host. This interface connected to the swarm.
func Create(interfaceName, localPeepIPAddr, hash, key, ttl, portRange string) {
	cmd := []string{"start", "-key", key, "-dev", interfaceName, "-ttl", ttl, "-hash", hash}
	if localPeepIPAddr != "dhcp" {
		cmd = append(cmd, "-ip", localPeepIPAddr)
	}
	if len(portRange) > 2 {
		cmd = append(cmd, "-ports", portRange)
	}
	out, err := exec.Command("p2p", cmd...).CombinedOutput()
	log.Check(log.FatalLevel, "Creating p2p interface "+string(out), err)
}

// Remove deletes P2P interface from the Resource Host.
func Remove(hash string) {
	log.Check(log.WarnLevel, "Removing p2p interface", exec.Command("p2p", "stop", "-hash", hash).Run())
}

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
			Remove(line[2])
		}
	}
	log.Check(log.WarnLevel, "Removing p2p interface from registered list", exec.Command("p2p", "stop", "--dev", name).Run())
	log.Check(log.WarnLevel, "Removing p2p interface from system", exec.Command("ip", "link", "delete", name).Run())
	log.Check(log.WarnLevel, "Disabling p2p link", exec.Command("ifconfig", name, "down").Run())
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

// UpdateKey sets new encryption key for the P2P instance to replace it during work.
func UpdateKey(hash, newkey, ttl string) {
	out, err := exec.Command("p2p", "set", "-key", newkey, "-ttl", ttl, "-hash", hash).CombinedOutput()
	log.Check(log.FatalLevel, "Updating p2p key "+string(out), err)
}

// Version returns version of the P2P on the Resource Host.
func Version() {
	out, err := exec.Command("p2p", "-v").CombinedOutput()
	log.Check(log.ErrorLevel, "Getting p2p version", err)
	fmt.Printf("%s", out)
}

// Peers prints list of the participants of the swarm.
func Peers(hash string) {
	args := []string{"show"}
	if hash != "" {
		args = append(args, "-hash", hash)
	}
	out, err := exec.Command("p2p", args...).CombinedOutput()
	log.Check(log.ErrorLevel, "Getting list of p2p participants", err)
	fmt.Printf("%s", out)
}

// Interfaces returns list of interfaces that is used by P2P in the system
func Interfaces() (list []net.Interface) {
	l, err := net.Interfaces()
	log.Check(log.ErrorLevel, "Getting list of p2p interfaces", err)

	out, err := exec.Command("p2p", "show", "--interfaces", "--all").CombinedOutput()
	log.Check(log.ErrorLevel, "Getting list of p2p interfaces "+string(out), err)

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		for _, f := range l {
			if f.Name == scanner.Text() {
				list = append(list, f)
			}
		}
	}

	return list
}

func Status(hash string) {

	args := []string{"status"}

	if hash != "" {
		args = append(args, "-hash", hash)
	}

	out, err := exec.Command("p2p", args...).CombinedOutput()

	log.Check(log.ErrorLevel, "Getting p2p status "+string(out), err)

	fmt.Printf("%s", out)
}
