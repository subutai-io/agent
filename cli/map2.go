package cli

import (
	"net"
	"strings"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	ovs "github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
	"github.com/nightlyone/lockfile"
	"path"
	"github.com/subutai-io/agent/lib/common"
)

var (
	nginxIncPath = path.Join(config.Agent.DataPrefix, "nginx/nginx-includes")
)

func ListPortMappings(protocol string) []string {
	mappings, err := db.GetAllMappings(protocol)
	log.Check(log.ErrorLevel, "Fetching port mappings", err)
	return mappings
}

func DeletePortMapping(protocol, sockInt, sockExt, domain string) {
	protocol = strings.ToLower(protocol)

	if protocol != "tcp" && protocol != "udp" && protocol != "http" && protocol != "https" {
		log.Error("Unsupported protocol \"" + protocol + "\"")
	}

	if (protocol == "http" || protocol == "https") && len(domain) == 0 {
		log.Error("\"-n domain\" is mandatory for http(s) protocol")
	}

	if protocol == "tcp" || protocol == "udp" {
		domain = protocol
	}

	if !ovs.ValidSocket(sockExt) {
		sockExt = "0.0.0.0:" + sockExt
	}
	mappings, err := db.FindMappings(protocol, sockExt, sockInt, domain)

	log.Check(log.ErrorLevel, "Fetching matching mappings", err)

	for i := 0; i < len(mappings); i++ {
		log.Check(log.ErrorLevel, "Removing mapping", db.RemoveMapping(mappings[i]))
	}

	mappings, _ = db.FindMappings(protocol, sockExt, "", domain)

	if len(mappings) == 0 {
		//todo delete nginx config file
	} else {
		//todo recreate nginx config file
	}

	//todo restart nginx
	//restart()
}

//todo USE template from string variable
func CreatePortMapping(protocol, sockInt, sockExt, domain, balancingPolicy string, sslBackend bool) {
	protocol = strings.ToLower(protocol)

	if protocol != "tcp" && protocol != "udp" && protocol != "http" && protocol != "https" {
		log.Error("Unsupported protocol \"" + protocol + "\"")
	}

	if (protocol == "http" || protocol == "https") && len(domain) == 0 {
		log.Error("\"-n domain\" is mandatory for http(s) protocol")
	}

	if protocol == "tcp" || protocol == "udp" {
		domain = protocol
	}

	if !ovs.ValidSocket(sockExt) {
		sockExt = "0.0.0.0:" + sockExt
	}

	if !ovs.ValidSocket(sockInt) {
		log.Error("Invalid internal socket \"" + sockInt + "\"")
	}

	if (strings.HasSuffix(sockExt, ":8443") || strings.HasSuffix(sockExt, ":8444") || strings.HasSuffix(sockExt, ":8086")) &&
		sockInt != "10.10.10.1:"+strings.Split(sockExt, ":")[1] {
		log.Error("Reserved system ports")
	}

	//add mapping

	var mappingLockFile = protocol + domain + sockInt + sockExt
	var lock lockfile.Lockfile
	var err error
	for lock, err = common.LockFile(mappingLockFile, "map"); err != nil; lock, err = common.LockFile(mappingLockFile, "map") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	portMapping := &db.PortMapping{
		Protocol:        protocol,
		ExternalSocket:  sockExt,
		InternalSocket:  sockInt,
		Domain:          domain,
		BalancingPolicy: balancingPolicy,
		SslBackend:      sslBackend,
	}

	db.SaveMapping(portMapping)

	//TODO for the same protocol socketExt and domain (re)create nginx config file and overwite existing if any
	//TODO when destroying container, we need to remove all related mappings by container IP == socketInt[0]
	// (without port so we have to keep socketIntIp in PortMapping struct or filter in code)

	if socket := strings.Split(sockExt, ":"); socket[0] == "0.0.0.0" {
		log.Info(ovs.GetIp() + ":" + socket[1])
	} else {
		log.Info(sockExt)
	}

	//restart nginx
	//restart()
}

func isPortFree(protocol, sockExt string) bool {
	switch protocol {
	case "tcp", "http", "https":
		if ln, err := net.Listen("tcp", sockExt); err == nil {
			ln.Close()
			return true
		}
	case "udp":
		if addr, err := net.ResolveUDPAddr("udp", sockExt); err == nil {
			if ln, err := net.ListenUDP("udp", addr); err == nil {
				ln.Close()
				return true
			}
		}
	}
	return false
}
