//"subutai map" command
//this is a handy shortcut for managing proxies that are normally managed via "subutai proxy" command
//this command is a helper that allows to create a proxy and add a server to it in one shot
//similarly it allows to remove a server from a proxy and remove the proxy if it becomes empty in one shot
//also it allows to list proxies and its servers in one shot

package cli

import (
	"strings"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/proxy"
	"path"
	"fmt"
)

var (
	nginxInc = path.Join(config.Agent.DataPrefix, "nginx/nginx-includes")
)

func GetPortMappings(protocol string) []string {
	protocol = strings.ToLower(protocol)

	var output []string
	proxies, err := proxy.GetProxies(protocol)
	log.Check(log.ErrorLevel, "Getting proxies", err)
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

	tag := fmt.Sprintf(proxy.TAGFORMAT, protocol, port, domain)
	if protocol == proxy.TCP || protocol == proxy.UDP {
		tag = fmt.Sprintf(proxy.TAGFORMAT, protocol, port, "stream")
	}

	if server != "" {
		err := proxy.RemoveProxiedServer(tag, server)
		log.Check(log.ErrorLevel, "Removing server", err)

		//if no servers left in proxy, remove it
		servers, err := proxy.FindProxiedServers(tag, "")
		log.Check(log.ErrorLevel, "Getting proxied servers from db", err)

		if len(servers) == 0 {
			err = proxy.RemoveProxy(tag)
			log.Check(log.ErrorLevel, "Removing proxy", err)
		}
	} else {
		err := proxy.RemoveProxy(tag)
		log.Check(log.ErrorLevel, "Removing proxy", err)
	}
}

func AddPortMapping(protocol, domain, loadBalancing string, port int, server, certPath string, redirect80Port, sslBackend bool) {
	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)

	tag := fmt.Sprintf(proxy.TAGFORMAT, protocol, port, domain)
	if protocol == proxy.TCP || protocol == proxy.UDP {
		tag = fmt.Sprintf(proxy.TAGFORMAT, protocol, port, "stream")
	}

	prxy, err := proxy.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)

	if prxy == nil {
		err = proxy.CreateProxy(protocol, domain, loadBalancing, tag, port, redirect80Port, sslBackend, certPath)
		log.Check(log.ErrorLevel, "Creating proxy", err)
		prxy, err = proxy.FindProxyByTag(tag)
		log.Check(log.ErrorLevel, "Getting proxy from db", err)
	}

	err = proxy.AddProxiedServer(tag, server)
	log.Check(log.ErrorLevel, "Adding server", err)

}
