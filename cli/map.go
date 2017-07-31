package cli

import (
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"fmt"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/gpg"
	ovs "github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
)

// MapPort exposes internal container ports to external RH interface. It supports udp, tcp, http(s) protocols and other reverse proxy features
func MapPort(protocol, internal, external, policy, domain, cert string, list, remove, sslbcknd bool) {
	if list {
		for _, v := range mapList(protocol) {
			fmt.Println(v)
		}
		return
	}

	if protocol != "tcp" && protocol != "udp" && protocol != "http" && protocol != "https" {
		log.Error("Unsupported protocol \"" + protocol + "\"")
	} else if protocol == "tcp" || protocol == "udp" {
		domain = protocol
	}

	port := external
	if ovs.ValidSocket(external) {
		port = strings.Split(external, ":")[1]
	} else {
		external = "0.0.0.0:" + port
	}

	switch {
	case (protocol == "http" || protocol == "https") && len(domain) == 0:
		log.Error("\"-d domain\" is mandatory for http protocol")
	case remove:
		mapRemove(protocol, external, domain, internal)
	case protocol == "https" && (len(cert) == 0 || !gpg.ValidatePem(cert)):
		log.Error("\"-c certificate\" is missing or invalid pem file")
	case len(internal) != 0 && !ovs.ValidSocket(internal):
		log.Error("Invalid internal socket \"" + internal + "\"")
	case (port == "8443" || port == "8444" || port == "8086") &&
		internal != "10.10.10.1:"+port:
		log.Error("Reserved system ports")
	case len(internal) != 0:
		// check external port and create nginx config
		if portIsNew(protocol, internal, domain, &external) {
			newConfig(protocol, external, domain, cert, sslbcknd)
		}

		// add containers to backend
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+external+"-"+domain+".conf",
			"#Add new host here", "	server "+internal+";", false)

		// save information to database
		saveMapToDB(protocol, external, domain, internal)
		containerMapToDB(protocol, external, domain, internal)
		balanceMethod(protocol, external, domain, policy)

		if strings.Contains(external, "0.0.0.0:") {
			log.Info(ovs.GetIp() + ":" + port)
		} else {
			log.Info(external)
		}
	case len(policy) != 0:
		balanceMethod(protocol, external, domain, policy)
	}
	restart()
}

func mapList(protocol string) (list []string) {
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning portmap database to get list", err)
	switch protocol {
	case "tcp", "udp", "http", "https":
		list = bolt.PortmapList(protocol)
	default:
		for _, v := range []string{"tcp", "udp", "http", "https"} {
			list = append(list, bolt.PortmapList(v)...)
		}
	}
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
	return
}

func mapRemove(protocol, external, domain, internal string) {
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning portmap database to remove mapping", err)
	defer bolt.Close()
	// Commenting this section out to insure config deletion even if db doesn't have it
	// if !bolt.PortInMap(protocol, external, domain, internal) {
	// 	return
	// }
	log.Debug("Removing mapping: " + protocol + " " + external + " " + domain + " " + internal)

	if bolt.PortMapDelete(protocol, external, domain, internal) > 0 {
		if strings.Contains(internal, ":") {
			internal = internal + ";"
		} else {
			internal = internal + ":"
		}
		addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+external+"-"+domain+".conf",
			"server "+internal, " ", true)
	} else {
		if bolt.PortMapDelete(protocol, external, domain, "") == 0 {
			bolt.PortMapDelete(protocol, external, "", "")
		}
		os.Remove(config.Agent.DataPrefix + "nginx-includes/" + protocol + "/" + external + "-" + domain + ".conf")
		if protocol == "https" {
			os.Remove(config.Agent.DataPrefix + "web/ssl/https-" + external + "-" + domain + ".key")
			os.Remove(config.Agent.DataPrefix + "web/ssl/https-" + external + "-" + domain + ".crt")
		}
	}
}

func isFree(protocol, external string) (res bool) {
	switch protocol {
	case "tcp", "http", "https":
		if ln, err := net.Listen("tcp", external); err == nil {
			ln.Close()
			res = true
		}
	case "udp":
		if addr, err := net.ResolveUDPAddr("udp", external); err == nil {
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

func portIsNew(protocol, internal, domain string, external *string) (new bool) {
	ext := strings.Split(*external, ":")
	if len(ext[1]) != 0 {
		if port, err := strconv.Atoi(ext[1]); err != nil || port < 1000 || port > 65536 {
			log.Error("Port number in \"external\" should be integer in range of 1000-65536")
		}
		if isFree(protocol, *external) {
			return true
		}

		bolt, err := db.New()
		log.Check(log.ErrorLevel, "Opening portmap database to read existing mappings", err)
		if !bolt.PortInMap(protocol, *external, "", "") {
			log.Error("Port is busy")
		} else if bolt.PortInMap(protocol, *external, domain, internal) {
			log.Error("Map is already exists")
		}
		new = !bolt.PortInMap(protocol, *external, domain, "")
		log.Check(log.WarnLevel, "Closing database", bolt.Close())
	} else {
		for ext[1] = strconv.Itoa(random(1000, 65536)); !isFree(protocol, ext[0]+":"+ext[1]); ext[1] = strconv.Itoa(random(1000, 65536)) {
			continue
		}
		*external = ext[0] + ":" + ext[1]
		new = true
	}
	return new
}

func newConfig(protocol, external, domain, cert string, sslbcknd bool) {
	log.Check(log.WarnLevel, "Creating nginx include folder",
		os.MkdirAll(config.Agent.DataPrefix+"nginx-includes/"+protocol, 0755))
	conf := config.Agent.DataPrefix + "nginx-includes/" + protocol + "/" + external + "-" + domain + ".conf"

	switch protocol {
	case "https":
		log.Check(log.ErrorLevel, "Creating certificate dirs", os.MkdirAll(config.Agent.DataPrefix+"/web/ssl/", 0755))
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/vhost-ssl.example", conf)
		addLine(conf, "return 301 https://$host$request_uri;  # enforce https", "	    return 301 https://$host:"+external+"$request_uri;  # enforce https", true)
		addLine(conf, "listen	443;", "	listen "+external+";", true)
		addLine(conf, "server_name DOMAIN;", "server_name "+domain+";", true)
		if sslbcknd {
			addLine(conf, "proxy_pass http://DOMAIN-upstream/;", "	proxy_pass https://https-"+strings.Replace(external, ":", "-", -1)+"-"+domain+";", true)
		} else {
			addLine(conf, "proxy_pass http://DOMAIN-upstream/;", "	proxy_pass http://https-"+strings.Replace(external, ":", "-", -1)+"-"+domain+";", true)
		}
		addLine(conf, "upstream DOMAIN-upstream {", "upstream https-"+strings.Replace(external, ":", "-", -1)+"-"+domain+" {", true)

		crt, key := gpg.ParsePem(cert)
		log.Check(log.WarnLevel, "Writing certificate body", ioutil.WriteFile(config.Agent.DataPrefix+"web/ssl/https-"+external+"-"+domain+".crt", crt, 0644))
		log.Check(log.WarnLevel, "Writing key body", ioutil.WriteFile(config.Agent.DataPrefix+"web/ssl/https-"+external+"-"+domain+".key", key, 0644))

		addLine(conf, "ssl_certificate /var/snap/subutai/current/web/ssl/UNIXDATE.crt;",
			"ssl_certificate "+config.Agent.DataPrefix+"web/ssl/https-"+external+"-"+domain+".crt;", true)
		addLine(conf, "ssl_certificate_key /var/snap/subutai/current/web/ssl/UNIXDATE.key;",
			"ssl_certificate_key "+config.Agent.DataPrefix+"web/ssl/https-"+external+"-"+domain+".key;", true)
	case "http":
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/vhost.example", conf)
		addLine(conf, "listen 	80;", "	listen "+external+";", true)
		addLine(conf, "return 301 http://$host$request_uri;", "	    return 301 http://$host:"+external+"$request_uri;", true)
		addLine(conf, "server_name DOMAIN;", "server_name "+domain+";", true)
		addLine(conf, "proxy_pass http://DOMAIN-upstream/;", "	proxy_pass http://http-"+strings.Replace(external, ":", "-", -1)+"-"+domain+";", true)
		addLine(conf, "upstream DOMAIN-upstream {", "upstream http-"+strings.Replace(external, ":", "-", -1)+"-"+domain+" {", true)
		if strings.HasSuffix(external, ":80") {
			httpRedirect(external, domain)
		}
	case "tcp":
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/stream.example", conf)
		addLine(conf, "listen PORT;", "	listen "+external+";", true)
	case "udp":
		fs.Copy(config.Agent.AppPrefix+"etc/nginx/tmpl/stream.example", conf)
		addLine(conf, "listen PORT;", "	listen "+external+" udp;", true)
	}
	addLine(conf, "server localhost:81;", " ", true)
	addLine(conf, "upstream PROTO-PORT {", "upstream "+protocol+"-"+strings.Replace(external, ":", "-", -1)+"-"+domain+" {", true)
	addLine(conf, "proxy_pass PROTO-PORT;", "	proxy_pass "+protocol+"-"+strings.Replace(external, ":", "-", -1)+"-"+domain+";", true)
}

func balanceMethod(protocol, external, domain, policy string) {
	replaceString := "upstream " + protocol + "-" + strings.Replace(external, ":", "-", -1) + "-" + domain + " {"
	replace := false
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning portmap database to check if port is mapped", err)
	if !bolt.PortInMap(protocol, external, domain, "") {
		log.Error("Port is not mapped")
	}
	switch policy {
	case "round-robin", "round_robin":
		policy = "#round-robin"
	//  "least_conn":
	case "least_time":
		if protocol == "tcp" {
			policy = policy + " connect"
		} else {
			policy = policy + " header"
			log.Warn("This policy is not supported in http upstream")
			return
		}
	case "hash":
		policy = policy + " $remote_addr"
	case "ip_hash":
		if protocol != "http" {
			log.Warn("ip_hash policy allowed only for http protocol")
			return
		}
	default:
		log.Debug("Unsupported balancing method \"" + policy + "\", ignoring")
		return
	}

	if p := bolt.GetMapMethod(protocol, external, domain); len(p) != 0 && p != policy {
		replaceString = "; #policy"
		replace = true
	} else if p == policy {
		return
	}
	log.Check(log.WarnLevel, "Saving map method", bolt.SetMapMethod(protocol, external, domain, policy))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	addLine(config.Agent.DataPrefix+"nginx-includes/"+protocol+"/"+external+"-"+domain+".conf",
		replaceString, "	"+policy+"; #policy", replace)
}

func httpRedirect(external, domain string) {
	var redirect = `server {
	    listen      80; #redirect
    	server_name ` + domain + `;
    	return 301 http://$host$request_uri;
}`

	addLine(config.Agent.DataPrefix+"nginx-includes/http/"+external+"-"+domain+".conf",
		"#redirect placeholder", redirect, true)

}

func saveMapToDB(protocol, external, domain, internal string) {
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning database to save portmap", err)
	if !bolt.PortInMap(protocol, external, domain, internal) {
		log.Check(log.WarnLevel, "Saving port map to database", bolt.PortMapSet(protocol, external, domain, internal))
	}
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
}

func containerMapToDB(protocol, external, domain, internal string) {
	bolt, err := db.New()
	log.Check(log.ErrorLevel, "Openning database to add portmap to container", err)
	for _, name := range bolt.ContainerByKey("ip", strings.Split(internal, ":")[0]) {
		bolt.ContainerMapping(name, protocol, external, domain, internal)
	}
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
}
