package cli

import (
	"math/rand"
	"net"
	"strconv"
	"time"

	"os"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
)

func MapTCP(internal, external string, remove bool) {
	// check port if set
	var new bool
	if len(external) != 0 {
		if port, err := strconv.Atoi(external); err != nil || port < 1000 || port > 65536 {
			log.Error("Parameter \"external\" should be integer in range of 1000-65536")
		}
		if isFree("tcp", external) {
			new = true
		} else {
			bolt, err := db.New()
			log.Check(log.ErrorLevel, "Openning portmap database", err)
			if !bolt.PortInMap("tcp", external) {
				log.Error("Port is busy")
			}
			log.Check(log.WarnLevel, "Closing database", bolt.Close())
		}
	} else {
		for external = strconv.Itoa(random(1000, 65536)); !isFree("tcp", external); external = strconv.Itoa(random(1000, 65536)) {
			continue
		}
		new = true
	}

	// copy nginx template
	if new {
		log.Check(log.WarnLevel, "Creating nginx include folder",
			os.MkdirAll(config.Agent.DataPrefix+"nginx-includes/tcp", 0755))
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/tcp-stream.example", config.Agent.DataPrefix+"nginx-includes/tcp/tcp-"+external+".conf")

		addLine(config.Agent.DataPrefix+"nginx-includes/tcp/tcp-"+external+".conf",
			"listen PORT;", "listen "+external+";", true)
		addLine(config.Agent.DataPrefix+"nginx-includes/tcp/tcp-"+external+".conf",
			"proxy_pass tcp-PORT;", "proxy_pass tcp-"+external+";", true)
		addLine(config.Agent.DataPrefix+"nginx-includes/tcp/tcp-"+external+".conf",
			"upstream tcp-PORT {", "upstream tcp-"+external+" {", true)
		addLine(config.Agent.DataPrefix+"nginx-includes/tcp/tcp-"+external+".conf",
			"server localhost:81;", " ", true)
	}

	// add containers to backend
	addLine(config.Agent.DataPrefix+"nginx-includes/tcp/tcp-"+external+".conf",
		"#Add new host here", "server "+internal+";", false)
	// save information to database
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning portmap database", err)
	log.Check(log.WarnLevel, "Saving port map to database", bolt.PortMapSet("tcp", internal, external))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	// reload nginx
	restart()
}

func MapUDP(internal, external string, remove bool)          {}
func MapHTTP(internal, external, domain string, remove bool) {}

func isFree(protocol, port string) bool {
	if ln, err := net.Listen(protocol, ":"+port); err == nil {
		ln.Close()
		return true
	}
	return false
}

func random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}
