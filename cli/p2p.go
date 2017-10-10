package cli

import (
	"fmt"
	"strings"

	"github.com/subutai-io/agent/lib/net/p2p"
	"github.com/subutai-io/agent/log"
)

// P2P function controls and configures the peer-to-peer network structure:
// the swarm which includes all hosts with same the same swarm hash and secret key.
//
// P2P is a base layer for Subutai environment networking:
// all containers in same environment are connected to each other via VXLAN tunnels and are accesses as if they were in one LAN.
// It doesn't matter where the containers are physically located.
func P2P(create, remove, update, list, peers bool, args []string) {
	if create {
		if len(args) > 8 {
			p2p.Create(args[3], args[7], args[4], args[5], args[6], args[8]) //p2p -c interfaceName hash key ttl localPeepIPAddr portRange

		} else if len(args) > 7 {
			if strings.Contains(args[7], "-") {
				p2p.Create(args[3], "dhcp", args[4], args[5], args[6], args[7]) //p2p -c interfaceName hash key ttl portRange
			} else {
				p2p.Create(args[3], args[7], args[4], args[5], args[6], "") //p2p -c interfaceName hash key ttl localPeepIPAddr
			}
		} else if len(args) > 6 {
			p2p.Create(args[3], "dhcp", args[4], args[5], args[6], "") //p2p -c interfaceName hash key ttl
		} else {
			log.Error("Wrong usage")
		}

	} else if update {
		if len(args) < 6 {
			log.Error("Wrong usage")
		}
		p2p.UpdateKey(args[3], args[4], args[5])

	} else if remove {
		if len(args) < 4 {
			log.Error("Wrong usage")
		}
		p2p.Remove(args[3])

	} else if peers {
		if len(args) < 3 {
			p2p.Peers(args[3])
		} else {
			p2p.Peers("")
		}
	}
}

// P2Pversion prints version of p2p daemon
func P2Pversion() {
	p2p.Version()
}

// P2PInterfaces prints list of interfaces used by P2P
func P2PInterfaces() {
	list, err := p2p.Interfaces()
	log.Check(log.ErrorLevel, "Getting list of p2p interfaces", err)

	for _, iface := range list {
		fmt.Println(iface.Name)
	}
}
