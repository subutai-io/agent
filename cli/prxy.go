package cli

import (
	"strings"
	"github.com/subutai-io/agent/log"
	"fmt"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/db"
)

const HTTP = "http"
const HTTPS = "https"

//TODO extract balancing policies to constants
//todo make mandatory parameter as required in CLI

//subutai prxy create -p https -n test.com -e 80 -t 123 [-b round_robin] [-r false] [-c path/to/cert] [--sslbackend]
//subutai prxy create -p http -n test.com -e 80 -t 123 [-b round_robin]
func CreateProxy(protocol, domain, balancingPolicy, tag string, port int, redirect80To443, sslBackend bool, certPath string) {
	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)
	balancingPolicy = strings.ToLower(balancingPolicy)
	tag = strings.ToLower(tag)

	//check if protocol is https or https
	checkArgument(protocol == HTTP || protocol == HTTPS, "Unsupported protocol %s", protocol)

	//check if port is specified and valid
	checkArgument(port == 80 || port == 443 || (port >= 1000 && port <= 65536),
		"External port must be one of [80, 443, 1000-65536] ")

	if balancingPolicy != "" {
		checkArgument(balancingPolicy == "round_robin" || balancingPolicy == "least_time" ||
			balancingPolicy == "hash" || balancingPolicy == "ip_hash",
			"Balancing policy must be one of [round_robin,least_time,hash,ip_hash]")
	}
	//default policy to round-robin
	checkCondition(len(balancingPolicy) > 0, func() {
		balancingPolicy = "round_robin"
	})

	if protocol == HTTPS {
		//check if supplied certificate file exists
		checkArgument(certPath == "" || fs.FileExists(certPath), "Certificate file %s does not exist", certPath)

		//check if supplied certificate file is valid
		checkArgument(certPath == "" || gpg.ValidatePem(certPath), "Certificate file %s is not valid")
	}

	//check if tag is new
	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Checking proxy in db", err)
	checkNotNil(proxy, "Proxy with tag %s already exists: %v", tag, proxy)

	//check if proxy with the same combination of protocol+domain+port does not exist
	proxies, err := db.FindProxies(protocol, domain, port)
	log.Check(log.ErrorLevel, "Checking proxy in db", err)
	checkArgument(len(proxies) == 0, "Proxy with such combination of protocol, domain and port already exists")

	//if redirection is requested (https only, otherwise ignored), check if port 80 for http+domain is not already reserved
	if protocol == HTTPS && redirect80To443 {
		proxies, err := db.FindProxies(HTTP, domain, 80)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		checkArgument(len(proxies) == 0, "Proxy to http://%s:80 already exists, can not redirect", domain)
	}

	//make optional flags consistent for http protocol
	if protocol == HTTP {
		redirect80To443 = false
		sslBackend = false
		certPath = ""
	}

	//save proxy
	proxy = &db.Proxy{
		Protocol:        protocol,
		Domain:          domain,
		Port:            port,
		Tag:             tag,
		Redirect80To443: redirect80To443,
		BalancingPolicy: balancingPolicy,
		SslBackend:      sslBackend,
		IsLetsEncrypt:   protocol == HTTPS && certPath == "",
	}

	log.Check(log.ErrorLevel, "Saving proxy to db", db.SaveProxy(proxy))

	applyConfig(tag, true)
}

func RemoveProxy(tag string) {
	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)
	checkNotNil(proxy, "Proxy not found by tag %s", tag)

}

func AddProxiedServer(tag, socket string) {

	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)
	checkNotNil(proxy, "Proxy not found by tag %s", tag)

	proxiedServers, err := db.FindProxiedServers(tag, socket)
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)
	checkState(len(proxiedServers) == 0, "Proxied server %v already exists", proxiedServers[0])

	proxiedServer := &db.ProxiedServer{
		ProxyTag: tag,
		Socket:   socket,
	}

	log.Check(log.ErrorLevel, "Saving proxied server to db", db.SaveProxiedServer(proxiedServer))

	applyConfig(tag, false)
}

func RemoveProxiedServer(tag, socket string) {
	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)
	checkNotNil(proxy, "Proxy not found by tag %s", tag)

	proxiedServers, err := db.FindProxiedServers(tag, socket)
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)
	checkState(len(proxiedServers) > 0, "Proxied server not found")

	log.Check(log.ErrorLevel, "Removing proxied server from db", db.RemoveProxiedServer(proxiedServers[0]))

	applyConfig(tag, false)
}

func applyConfig(tag string, creating bool) {
	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)
	checkNotNil(proxy, "Proxy not found by tag %s", tag)

	proxiedServers, err := db.FindProxiedServers(tag, "")
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)

	//todo lock config file
	if len(proxiedServers) > 0 {
		//todo (re)create config
	} else {
		//todo make sure that empty backend servers dont crash nginx
		if (creating) {
			//TODO for LE certs, obtain them via certbot; for self-signed certs, parse and copy certs to web/ssl folder
		} else {
			//todo remove config and certs
		}
	}

	//todo reload nginx
}

//utilities
func checkArgument(condition bool, errMsg string, vals ...interface{}) {
	checkState(condition, errMsg, vals)
}

func checkNotNil(object interface{}, errMsg string, vals ...interface{}) {
	checkState(object != nil, errMsg, vals)
}

func checkState(condition bool, errMsg string, vals ...interface{}) {
	checkCondition(condition, func() {
		log.Error(fmt.Sprint(errMsg, vals))
	})
}

func checkCondition(condition bool, fallback func()) {
	if !condition {
		fallback()
	}
}
