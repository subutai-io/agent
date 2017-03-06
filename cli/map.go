package cli

import (
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/fs"
	ovs "github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
)

func MapPort(protocol, internal, external string, remove bool, domain ...string) {
	//validate args
	if protocol == "http" && len(domain[0]) == 0 {
		log.Error("\"-d domain\" is mandatory for http protocol")
	}

	if !validSocket(internal) {
		log.Error("Parameter \"internal\" should be in ip:port format")
	}

	// check external port and create nginx config
	if portIsNew(protocol, &external, domain) {
		newConfig(protocol, external, domain)
	}

	// add containers to backend
	addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+external+".conf",
		"#Add new host here", "server "+internal+";", false)

	// save information to database
	saveMapToDB(protocol, internal, external, domain)

	// reload nginx
	restart()

	log.Info(ovs.GetIp() + ":" + external)
}

func isFree(protocol, port string) (res bool) {
	switch protocol {
	case "tcp", "http":
		if ln, err := net.Listen("tcp", ovs.GetIp()+":"+port); err == nil {
			ln.Close()
			res = true
		}
	case "udp":
		if addr, err := net.ResolveUDPAddr("udp", ovs.GetIp()+":"+port); err == nil {
			if ln, err := net.ListenUDP("udp", addr); err == nil {
				ln.Close()
				res = true
			}
		}
	}
	return
}

func random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

func validSocket(socket string) bool {
	if addr := strings.Split(socket, ":"); len(addr) == 2 {
		if _, err := net.ResolveIPAddr("ip4", addr[0]); err == nil {
			if _, err := strconv.Atoi(addr[1]); err == nil {
				return true
			}
		}
	}
	return false
}

func portIsNew(protocol string, external *string, domain []string) (new bool) {
	if len(*external) != 0 {
		if port, err := strconv.Atoi(*external); err != nil || port < 1000 || port > 65536 {
			log.Error("Parameter \"external\" should be integer in range of 1000-65536")
		}
		if isFree(protocol, *external) {
			new = true
		} else {
			bolt, err := db.New()
			log.Check(log.ErrorLevel, "Openning portmap database", err)
			if !bolt.PortInMap(protocol, *external, domain) {
				log.Error("Port is busy")
			}
			log.Check(log.WarnLevel, "Closing database", bolt.Close())
		}
	} else {
		for *external = strconv.Itoa(random(1000, 65536)); !isFree(protocol, *external); *external = strconv.Itoa(random(1000, 65536)) {
			continue
		}
		new = true
	}
	return
}

func newConfig(protocol, port string, domain []string) {
	log.Check(log.WarnLevel, "Creating nginx include folder",
		os.MkdirAll(config.Agent.DataPrefix+"nginx-includes/"+protocol, 0755))

	switch protocol {
	case "http":
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/vhost.example",
			config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf")
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
			"listen 	80;", "listen "+port+";", true)
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
			"server_name DOMAIN;", "server_name "+domain[0]+";", true)
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
			"proxy_pass http://DOMAIN-upstream/;", "proxy_pass http://http-"+port+";", true)
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
			"upstream DOMAIN-upstream {", "upstream http-"+port+" {", true)
	case "tcp":
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/stream.example",
			config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf")
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
			"listen PORT;", "listen "+port+";", true)
	case "udp":
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/stream.example",
			config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf")
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
			"listen PORT;", "listen "+port+" udp;", true)
	}
	addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
		"server localhost:81;", " ", true)
	addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
		"upstream PROTO-PORT {", "upstream "+protocol+"-"+port+" {", true)
	addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+port+".conf",
		"proxy_pass PROTO-PORT;", "proxy_pass "+protocol+"-"+port+";", true)
}

func saveMapToDB(protocol, internal, external string, domain []string) {
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning portmap database", err)
	log.Check(log.WarnLevel, "Saving port map to database", bolt.PortMapSet(protocol, internal, external, domain))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
}
