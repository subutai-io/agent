package cli

import (
	"os"
	"strings"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/log"
	"path"
	"fmt"
	"io/ioutil"
)

var (
	nginxInc = path.Join(config.Agent.DataPrefix, "nginx/nginx-includes")
)

func GetPortMappings(protocol string) []string {
	protocol = strings.ToLower(protocol)

	var output []string
	proxies := GetProxies(protocol)
	for _, p := range proxies {
		if protocol == p.Proxy.Protocol || protocol == "" {
			for _, server := range p.Servers {
				line := fmt.Sprintf("%s\t%d\t%s\t%s", p.Proxy.Protocol, p.Proxy.Port, server.Socket, p.Proxy.Domain)
				output = append(output, line)
			}
		}
	}

	return output
}

func RemovePortMapping(protocol, domain string, port int, server string) {
	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)

	tag := fmt.Sprintf("%s-%d-%s", protocol, port, domain)
	if protocol == TCP || protocol == UDP {
		tag = fmt.Sprintf("%s-%d-stream", protocol, port)
	}

	if server != "" {
		RemoveProxiedServer(tag, server)
	} else {
		RemoveProxy(tag)
		return
	}

	servers, err := db.FindProxiedServers(tag, "")
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)

	if len(servers) == 0 {
		RemoveProxy(tag)
	}
}

func AddPortMapping(protocol, domain, loadBalancing string, port int, server, certPath string, redirect80Port, sslBackend bool) {
	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)

	tag := fmt.Sprintf("%s-%d-%s", protocol, port, domain)
	if protocol == TCP || protocol == UDP {
		tag = fmt.Sprintf("%s-%d-stream", protocol, port)
	}

	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)

	if proxy == nil {
		CreateProxy(protocol, domain, loadBalancing, tag, port, redirect80Port, sslBackend, certPath)
		proxy, err = db.FindProxyByTag(tag)
		log.Check(log.ErrorLevel, "Getting proxy from db", err)
	}

	AddProxiedServer(tag, server)
}

//todo remove after one version
func MapRemove(protocol, sockExt, domain, sockInt string) {
	log.Debug("Removing mapping: " + protocol + " " + sockExt + " " + domain + " " + sockInt)

	if sockInt != "" {
		if checkPort(protocol, sockExt, domain, sockInt) {
			if deletePortMap(protocol, sockExt, domain, sockInt) > 0 {
				if strings.Contains(sockInt, ":") {
					sockInt = sockInt + ";"
				} else {
					sockInt = sockInt + ":"
				}
				addLine(path.Join(nginxInc, protocol, sockExt+"-"+domain+".conf"),
					"server "+sockInt, " ", true)
			} else {
				if deletePortMap(protocol, sockExt, domain, "") == 0 {
					deletePortMap(protocol, sockExt, "", "")
				}
				os.Remove(path.Join(nginxInc, protocol, sockExt+"-"+domain+".conf"))
				if protocol == "https" {
					os.Remove(path.Join(selfSignedCertsDir, "https-"+sockExt+"-"+domain+".key"))
					os.Remove(path.Join(selfSignedCertsDir, "https-"+sockExt+"-"+domain+".crt"))
				}
			}
		}
	} else {
		if deletePortMap(protocol, sockExt, domain, "") == 0 {
			deletePortMap(protocol, sockExt, "", "")
		}
		os.Remove(path.Join(nginxInc, protocol, sockExt+"-"+domain+".conf"))
		if protocol == "https" {
			os.Remove(path.Join(selfSignedCertsDir, "https-"+sockExt+"-"+domain+".key"))
			os.Remove(path.Join(selfSignedCertsDir, "https-"+sockExt+"-"+domain+".crt"))
		}
	}
}

func checkPort(protocol, external, domain, internal string) bool {
	res, err := db.INSTANCE.PortInMap(protocol, external, domain, internal)
	log.Check(log.ErrorLevel, "Checking port mapping in db", err)
	return res
}

func deletePortMap(protocol, sockExt, domain, sockInt string) int {
	left, err := db.INSTANCE.PortMapDelete(protocol, sockExt, domain, sockInt)
	log.Check(log.ErrorLevel, "Removing port mapping from db", err)
	return left
}

// addLine adds, removes, replaces and checks if line exists in specified file
func addLine(path, after, line string, replace bool) bool {
	f, err := ioutil.ReadFile(path)
	if !log.Check(log.DebugLevel, "Cannot read file "+path, err) {
		lines := strings.Split(string(f), "\n")
		for k, v := range lines {
			if strings.Contains(v, after) {
				if line != "" {
					if replace {
						log.Debug("Replacing " + lines[k] + " with " + line)
						lines[k] = line
					} else {
						log.Debug("Adding " + line + " after " + lines[k])
						lines[k] = after + "\n" + line
					}
				} else {
					return true
				}
			}
		}
		str := strings.Join(lines, "\n")
		log.Check(log.FatalLevel, "Writing new proxy config",
			ioutil.WriteFile(path, []byte(str), 0744))
	}
	return false
}
