package cli

import (
	"strings"
	"github.com/subutai-io/agent/log"
	"fmt"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/config"
	"path"
	"os"
	"strconv"
	"github.com/subutai-io/agent/lib/common"
)

const HTTP = "http"
const HTTPS = "https"

//for http and LE certs only
//place-holders: {domain}
const letsEncryptWellKnownSection = `
location /.well-known {                                                                                                                                                                    
	default_type "text/plain";                                                                                                                                                             
	rewrite /.well-known/(.*) /$1 break;                                                                                                                                                   
	root /var/lib/subutai/letsencrypt/webroot/{domain}/.well-known/;                                                                                                         
}
`

//for https only
//place-holders: {domain}
const redirect80to443Section = `
server {
	listen 80;
	server_name {domain};
	return 301 https://$host:443$request_uri;  # enforce https
}
`

//http & https
//place-holders: {protocol}, {port}, {domain}, {policy}, {servers}, {ssl}
const webConfig = `
upstream {protocol}-{port}-{domain}{
{policy}

{servers}
}                                                                                                                                                                                       

server {
    listen {port}
    server_name {domain};
    client_max_body_size 1G;
	
{ssl}
	
    error_page 497	https://$host$request_uri;
	
    location / {
        proxy_pass         http://{protocol}-{port}-{domain}; 
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   Host $http_host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}

`

//place-holders: {domain}
const letsEncryptSslDirectives = `
    ssl on;
    ssl_certificate /var/lib/subutai/letsencrypt/live/{domain}/cert.pem;
    ssl_certificate_key /var/lib/subutai/letsencrypt/live/{domain}/privkey.pem;
`

//place-holders: {domain}
const selfSignedSslDirectives = `
    ssl on;
    ssl_certificate /var/lib/subutai/web/ssl/{domain}.crt;
    ssl_certificate_key /var/lib/subutai/web/ssl/{domain}.key;
`

var selfSignedCertsDir = path.Join(config.Agent.DataPrefix, "/web/ssl")
var letsEncryptDir = path.Join(config.Agent.DataPrefix, "/letsencrypt")
var letsEncryptWebRootDir = path.Join(letsEncryptDir, "/webroot")
var letsEncryptCertsDir = path.Join(letsEncryptDir, "/live")

func init() {
	makeDir(selfSignedCertsDir)
	makeDir(letsEncryptDir)
	makeDir(letsEncryptWebRootDir)
	makeDir(letsEncryptCertsDir)
}

type ProxyNServers struct {
	Proxy   db.Proxy
	Servers []db.ProxiedServer
}

func GetProxies(protocol string) []ProxyNServers {
	var proxyNServers []ProxyNServers

	proxies, err := db.FindProxies(protocol, "", 0)
	log.Check(log.ErrorLevel, "Getting proxies from db", err)

	for _, proxy := range proxies {
		proxiedServers, err := db.FindProxiedServers(proxy.Tag, "")
		log.Check(log.ErrorLevel, "Getting proxied servers from db", err)

		proxyNServers = append(proxyNServers, ProxyNServers{Proxy: proxy, Servers: proxiedServers})
	}

	return proxyNServers
}

//TODO extract balancing policies to constants
//todo make mandatory parameter as required in CLI

//subutai prxy create -p https -n test.com -e 80 -t 123 [-b round_robin] [--redirect] [-c path/to/cert] [--sslbackend]
//subutai prxy create -p http -n test.com -e 80 -t 123 [-b round_robin]
func CreateProxy(protocol, domain, loadBalancing, tag string, port int, redirect80To443, sslBackend bool, certPath string) {
	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)
	loadBalancing = strings.ToLower(loadBalancing)
	tag = strings.ToLower(tag)

	//check if protocol is https or https
	checkArgument(protocol == HTTP || protocol == HTTPS, "Unsupported protocol %s", protocol)

	//check if port is specified and valid
	checkArgument(port == 80 || port == 443 || (port >= 1000 && port <= 65536),
		"External port must be one of [80, 443, 1000-65536] ")

	if loadBalancing != "" {
		checkArgument(loadBalancing == "round_robin" || loadBalancing == "least_time" ||
			loadBalancing == "hash" || loadBalancing == "ip_hash",
			"Balancing policy must be one of [round_robin,least_time,hash,ip_hash]")
	}
	//default policy to round-robin
	checkCondition(len(loadBalancing) > 0, func() {
		loadBalancing = "round_robin"
	})

	if protocol == HTTPS {
		//check if supplied certificate file exists
		checkArgument(certPath == "" || fs.FileExists(certPath), "Certificate file %s does not exist", certPath)

		//check if supplied certificate file is valid
		checkArgument(certPath == "" || gpg.ValidatePem(certPath), "Certificate file %s is not valid", certPath)
	}

	//check if tag is new
	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Checking proxy in db", err)
	checkState(proxy == nil, "Proxy with tag %s already exists", tag)

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
		LoadBalancing:   loadBalancing,
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

	deleteProxy(proxy)

	reloadNginx()
}

func AddProxiedServer(tag, socket string) {
	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)
	checkNotNil(proxy, "Proxy not found by tag %s", tag)

	proxiedServers, err := db.FindProxiedServers(tag, socket)
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)
	checkState(len(proxiedServers) == 0, "Proxied server already exists")

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

	log.Check(log.ErrorLevel, "Removing proxied server from db", db.RemoveProxiedServer(&proxiedServers[0]))

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

		//create config
		createConfig(proxy, proxiedServers)
	} else {
		//todo make sure that empty backend servers dont crash nginx
		if (creating) {

			log.Debug("Creating initial config file")
			if proxy.IsLetsEncrypt {
				//1) create http config with LE section
				//todo
				//2) reload nginx
				reloadNginx()
				//3) run certbot
				//todo
			} else {
				//1) copy certs to self signed certs directory
				//todo
			}
		} else {
			deleteProxy(proxy)
		}
	}

	reloadNginx()
}

func createConfig(proxy *db.Proxy, servers []db.ProxiedServer) {
	//todo
	//place-holders: {protocol}, {port}, {domain}, {policy}, {servers}, {ssl}
	effectiveConfig := strings.Replace(webConfig, "{protocol}", proxy.Protocol, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{port}", strconv.Itoa(proxy.Port), -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{domain}", proxy.Domain, -1)

	//todo policy

	//servers
	serversConfig := ""
	for i := 0; i < len(servers); i++ {
		serversConfig += "    " + servers[i].Socket + ";\n"
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{servers}", serversConfig, -1)

	//ssl
	sslConfig := ""
	if proxy.IsLetsEncrypt {
		sslConfig = strings.Replace(letsEncryptSslDirectives, "{domain}", proxy.Domain, -1)
	} else {

		sslConfig = strings.Replace(selfSignedSslDirectives, "{domain}", proxy.Domain, -1)
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{ssl}", sslConfig, -1)

	println(effectiveConfig)
}

func deleteProxy(proxy *db.Proxy) {
	//remove cfg file
	removeConfig(*proxy)

	//remove domain certificates
	//todo remove certs from relevant directory

	proxiedServers, err := db.FindProxiedServers(proxy.Tag, "")
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)

	//remove proxied servers from db
	for _, server := range proxiedServers {
		log.Check(log.ErrorLevel, "Removing proxied server from db", db.RemoveProxiedServer(&server))
	}

	//remove proxy from db
	log.Check(log.ErrorLevel, "Removing proxy from db", db.RemoveProxy(proxy))
}

func composeConfigPath(proxy db.Proxy) string {
	return proxy.Protocol + "-" + proxy.Domain + "-" + strconv.Itoa(proxy.Port)
}

func removeConfig(proxy db.Proxy) {
	cfgPath := composeConfigPath(proxy)
	err := fs.DeleteFile(cfgPath)
	if !os.IsNotExist(err) {
		log.Check(log.ErrorLevel, "Removing config file "+cfgPath, err)
	}
}

func reloadNginx() {
	//todo uncomment
	log.Debug("Reloading nginx")
	//out, err := exec.Command("service", "subutai-nginx", "reload").CombinedOutput()
	//log.Check(log.FatalLevel, "Reloading nginx "+string(out), err)
}

//utilities

func makeDir(path string) {
	if !fs.FileExists(path) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			log.Error("Failed to create directory " + path)
		}
	}
}

func checkArgument(condition bool, errMsg string, vals ...interface{}) {
	checkState(condition, errMsg, vals...)
}

func checkNotNil(object interface{}, errMsg string, vals ...interface{}) {
	checkState(!common.IsZeroOfUnderlyingType(object), errMsg, vals...)
}

func checkState(condition bool, errMsg string, vals ...interface{}) {
	log.Debug(condition)
	checkCondition(condition, func() {
		log.Error(fmt.Sprintf(errMsg, vals...))
	})
}

func checkCondition(condition bool, fallback func()) {
	if !condition {
		fallback()
	}
}
