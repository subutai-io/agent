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
	"io/ioutil"
	"regexp"
	"os/exec"
	exec2 "github.com/subutai-io/agent/lib/exec"
	"path/filepath"
	"sort"
	"net"
	"github.com/subutai-io/agent/agent/util"
	"github.com/nightlyone/lockfile"
	"time"
	"github.com/subutai-io/agent/lib/common"
)

const HTTP = "http"
const HTTPS = "https"
const UDP = "udp"
const TCP = "tcp"

const TAGFORMAT = "%s-%d-%s"

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
const redirect80Section = `

server {
	listen 80;
	server_name {domain};
	return 301 https://$host:{port}$request_uri;  # enforce https
}

`

//place-holders: {protocol}, {port}, {load-balancing}, {servers}, {udp}
const streamConfig = `
upstream {protocol}-{port} {
    {load-balancing}

{servers}
}

server {
	listen {port} {udp};
	proxy_pass {protocol}-{port};
}

`

//http & https
//place-holders: {protocol}, {port}, {domain}, {load-balancing}, {servers}, {ssl}
const webConfig = `
upstream {protocol}-{port}-{domain}{
    {load-balancing}

{servers}
}                                                                                                                                                                                       

server {
    listen {port};
    server_name {domain};
    client_max_body_size 1G;
	
{ssl}
	
    error_page 497	https://$host$request_uri;
	
    location / {
        proxy_pass         http{ssl-backend}://{protocol}-{port}-{domain}; 
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   Host $http_host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

	{well-known}
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
    ssl_certificate /var/lib/subutai/web/ssl/{domain}/cert.pem;
    ssl_certificate_key /var/lib/subutai/web/ssl/{domain}/privkey.pem;
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

	makeDir(path.Join(nginxInc, HTTPS))
	makeDir(path.Join(nginxInc, HTTP))
	makeDir(path.Join(nginxInc, TCP))
	makeDir(path.Join(nginxInc, UDP))
}

func MigrateMappings() {

	var streamMappings []db.PortMap
	for _, v := range []string{"tcp", "udp"} {
		l, err := db.INSTANCE.GetAllPortMappings(v)
		if !log.Check(log.WarnLevel, "Reading old port mappings from db", err) {
			streamMappings = append(streamMappings, l...)
		}
	}
	streamMap := make(map[string]*ProxyNServers) //key format "protocol_externalsocket"
	for _, m := range streamMappings {
		port, _ := strconv.Atoi(strings.Split(m.ExternalSocket, ":")[1])
		key := fmt.Sprintf(TAGFORMAT, m.Protocol, port, "stream")
		streamMap[key] = &ProxyNServers{Proxy: db.Proxy{
			Domain:   m.Domain,
			Protocol: m.Protocol,
			Port:     port,
			Tag:      key,
		}, Servers: []db.ProxiedServer{}}
	}

	for _, m := range streamMappings {
		port, _ := strconv.Atoi(strings.Split(m.ExternalSocket, ":")[1])
		portMap := streamMap[fmt.Sprintf(TAGFORMAT, m.Protocol, port, "stream")]
		portMap.Servers = append(portMap.Servers, db.ProxiedServer{ProxyTag: portMap.Proxy.Tag, Socket: m.InternalSocket})
	}

	var webMappings []db.PortMap
	for _, v := range []string{"http", "https"} {
		l, err := db.INSTANCE.GetAllPortMappings(v)
		if !log.Check(log.WarnLevel, "Reading old port mappings from db", err) {
			webMappings = append(webMappings, l...)
		}
	}
	webMap := make(map[string]*ProxyNServers) //key format "protocol_domain_externalsocket"
	for _, m := range webMappings {
		port, _ := strconv.Atoi(strings.Split(m.ExternalSocket, ":")[1])
		key := fmt.Sprintf(TAGFORMAT, m.Protocol, port, m.Domain)
		webMap[key] = &ProxyNServers{Proxy: db.Proxy{
			Domain:   m.Domain,
			Protocol: m.Protocol,
			Port:     port,
			Tag:      key,
		}, Servers: []db.ProxiedServer{}}
	}

	for _, m := range webMappings {
		port, _ := strconv.Atoi(strings.Split(m.ExternalSocket, ":")[1])
		portMap := webMap[fmt.Sprintf(TAGFORMAT, m.Protocol, port, m.Domain)]
		portMap.Servers = append(portMap.Servers, db.ProxiedServer{ProxyTag: portMap.Proxy.Tag, Socket: m.InternalSocket})
	}

	if len(streamMap) == 0 && len(webMap) == 0 {
		return
	}

	//migrate https
	for _, v := range webMap {
		if v.Proxy.Protocol == HTTPS {
			//copy cert into temp file
			certName := fmt.Sprintf("%s-0.0.0.0:%d-%s", v.Proxy.Protocol, v.Proxy.Port, v.Proxy.Domain)
			_, err := exec2.ExecuteWithBash("cat " + path.Join(selfSignedCertsDir, certName+".crt") + " " + path.Join(selfSignedCertsDir, certName+".key") + " > /tmp/" + certName)
			log.Check(log.WarnLevel, "Copying certificate", err)
			proxy := &db.Proxy{
				Protocol:       v.Proxy.Protocol,
				Domain:         v.Proxy.Domain,
				Port:           v.Proxy.Port,
				Tag:            v.Proxy.Tag,
				CertPath:       "/tmp/" + certName,
				Redirect80Port: true,
				LoadBalancing:  "rr",
				SslBackend:     false,
			}

			//create proxy
			log.Check(log.WarnLevel, "Saving proxy to db", db.SaveProxy(proxy))

			//copy certs
			certDir := path.Join(selfSignedCertsDir, proxy.Domain+"-"+strconv.Itoa(proxy.Port))
			log.Check(log.WarnLevel, "Creating cert dir", os.MkdirAll(certDir, 0755))
			crt, key := util.ParsePem(proxy.CertPath)
			log.Check(log.WarnLevel, "Writing certificate", ioutil.WriteFile(path.Join(certDir, "cert.pem"), crt, 0644))
			log.Check(log.WarnLevel, "Writing key", ioutil.WriteFile(path.Join(certDir, "privkey.pem"), key, 0644))

			//add servers
			for _, s := range v.Servers {
				proxiedServer := &db.ProxiedServer{
					ProxyTag: s.ProxyTag,
					Socket:   s.Socket,
				}

				log.Check(log.WarnLevel, "Saving proxied server to db", db.SaveProxiedServer(proxiedServer))
			}

			cfg := createHttpHttpsConfig(proxy, v.Servers)
			//apply config
			log.Check(log.ErrorLevel, "Writing nginx config", ioutil.WriteFile(path.Join(nginxInc, proxy.Protocol, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"), []byte(cfg), 0744))

			//remove old mapping
			MapRemove(v.Proxy.Protocol, "0.0.0.0:"+strconv.Itoa(v.Proxy.Port), v.Proxy.Domain, "")

		}
	}

	//migrate http
	for _, v := range webMap {
		if v.Proxy.Protocol == HTTP {
			//for port 80 check if domain is not reserved by redirected https
			if v.Proxy.Port == 80 {
				proxies, _ := db.FindProxies(HTTPS, v.Proxy.Domain, 0)
				if len(proxies) > 0 {
					//remove old mapping
					MapRemove(v.Proxy.Protocol, "0.0.0.0:"+strconv.Itoa(v.Proxy.Port), v.Proxy.Domain, "")
					//skip it
					continue
				}
			}

			proxy := &db.Proxy{
				Protocol:       v.Proxy.Protocol,
				Domain:         v.Proxy.Domain,
				Port:           v.Proxy.Port,
				Tag:            v.Proxy.Tag,
				CertPath:       "",
				Redirect80Port: false,
				LoadBalancing:  "rr",
				SslBackend:     false,
			}
			//create proxy
			log.Check(log.WarnLevel, "Saving proxy to db", db.SaveProxy(proxy))

			//add servers
			for _, s := range v.Servers {
				proxiedServer := &db.ProxiedServer{
					ProxyTag: s.ProxyTag,
					Socket:   s.Socket,
				}

				log.Check(log.WarnLevel, "Saving proxied server to db", db.SaveProxiedServer(proxiedServer))
			}

			cfg := createHttpHttpsConfig(proxy, v.Servers)
			//apply config
			log.Check(log.ErrorLevel, "Writing nginx config", ioutil.WriteFile(path.Join(nginxInc, proxy.Protocol, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"), []byte(cfg), 0744))

			//remove old mapping
			MapRemove(v.Proxy.Protocol, "0.0.0.0:"+strconv.Itoa(v.Proxy.Port), v.Proxy.Domain, "")

		}
	}

	//migrate tcp/udp
	for _, v := range streamMap {
		//check if the same port is not used by other mappings
		proxies, _ := db.FindProxies("", "", v.Proxy.Port)
		if len(proxies) > 0 || !(v.Proxy.Port >= 1000 && v.Proxy.Port <= 65535) {
			//remove old mapping
			MapRemove(v.Proxy.Protocol, "0.0.0.0:"+strconv.Itoa(v.Proxy.Port), v.Proxy.Protocol, "")
			//skip it
			continue
		}

		proxy := &db.Proxy{
			Protocol:       v.Proxy.Protocol,
			Domain:         v.Proxy.Domain,
			Port:           v.Proxy.Port,
			Tag:            v.Proxy.Tag,
			CertPath:       "rr",
			Redirect80Port: false,
			LoadBalancing:  "",
			SslBackend:     false,
		}
		//create proxy
		log.Check(log.WarnLevel, "Saving proxy to db", db.SaveProxy(proxy))

		//add servers
		for _, s := range v.Servers {
			proxiedServer := &db.ProxiedServer{
				ProxyTag: s.ProxyTag,
				Socket:   s.Socket,
			}

			log.Check(log.WarnLevel, "Saving proxied server to db", db.SaveProxiedServer(proxiedServer))
		}

		cfg := createTcpUdpConfig(proxy, v.Servers)
		//apply config
		log.Check(log.ErrorLevel, "Writing nginx config", ioutil.WriteFile(path.Join(nginxInc, proxy.Protocol, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"), []byte(cfg), 0744))

		//remove old mapping
		MapRemove(v.Proxy.Protocol, "0.0.0.0:"+strconv.Itoa(v.Proxy.Port), v.Proxy.Protocol, "")
	}

	reloadNginx()

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

//subutai prxy create -p https -n test.com -e 80 -t 123 [-b round_robin] [--redirect] [-c path/to/cert] [--sslbackend]
//subutai prxy create -p http -n test.com -e 80 -t 123 [-b round_robin]
func CreateProxy(protocol, domain, loadBalancing, tag string, port int, redirect80Port, sslBackend bool, certPath string) {
	var err error = nil
	var lock lockfile.Lockfile
	for lock, err = common.LockFile("port", "proxy"); err != nil; lock, err = common.LockFile("port", "proxy") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)
	loadBalancing = strings.ToLower(loadBalancing)
	tag = strings.ToLower(tag)

	//check if protocol is https or https
	checkArgument(protocol == HTTP || protocol == HTTPS || protocol == TCP || protocol == UDP,
		"Unsupported protocol %s", protocol)

	//check if port is specified and valid
	checkArgument(port == 80 || port == 443 || (port >= 1000 && port <= 65535),
		"External port must be one of [80, 443, 1000-65535] ")

	//check domain
	if protocol == HTTP || protocol == HTTPS {
		checkArgument(domain != "", "Domain is required for http/https proxies")
	}

	if loadBalancing != "" {
		checkArgument(loadBalancing == "rr" || loadBalancing == "lcon" ||
			loadBalancing == "sticky",
			"Balancing policy must be one of [rr,sticky,lcon]")
	}
	//default policy to round-robin
	checkCondition(len(loadBalancing) > 0, func() {
		loadBalancing = "rr"
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
	checkState(len(proxies) == 0, "Proxy with such combination of protocol, domain and port already exists")

	if protocol == TCP || protocol == UDP {
		//check port range
		checkArgument(port >= 1000, "For tcp/udp protocols port must be >= 1000")

		//check port availability
		proxies, err := db.FindProxies("", "", port)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)

		checkCondition(len(proxies) == 0, func() {
			log.Error(fmt.Sprintf("Proxy to %s://%s:%d already exists, can not create proxy",
				proxies[0].Protocol, proxies[0].Domain, port))
		})

	} else {
		//HTTP/HTTPS
		//check if the same tcp/udp port is not reserved
		//and check if the same http/https port and domain is not reserved
		tcpProxies, err := db.FindProxies(TCP, "", port)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		udpProxies, err := db.FindProxies(UDP, "", port)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		httpProxies, err := db.FindProxies(HTTP, domain, port)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		httpsProxies, err := db.FindProxies(HTTPS, domain, port)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)

		proxies := append(tcpProxies, udpProxies...)
		proxies = append(proxies, httpProxies...)
		proxies = append(proxies, httpsProxies...)

		checkCondition(len(proxies) == 0, func() {
			log.Error(fmt.Sprintf("Proxy to %s://%s:%d already exists, can not create proxy",
				proxies[0].Protocol, proxies[0].Domain, port))
		})
	}

	//if redirection is requested (https only, otherwise ignored), check if port 80 for http+domain is not already reserved
	//also check in case mapping with LE certificate is requested
	if protocol == HTTPS && (redirect80Port || proxy.IsLE()) {
		//check all http proxies with 80 port
		proxies, err := db.FindProxies(HTTP, domain, 80)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		checkState(len(proxies) == 0, "Proxy to http://%s:80 already exists, can not create proxy", domain)

		//check https proxies with redirect to 80 port
		proxies, err = db.FindProxies(HTTPS, domain, 0)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		for _, prxy := range proxies {
			//find proxies with redirected 80 port
			checkState(!prxy.Redirect80Port,
				"Proxy to https://%s:%d with port 80 redirection already exists, can not create proxy", domain, prxy.Port)
			//find LE proxies with the same domain
			checkState(!prxy.IsLE(),
				"Proxy to https://%s:%d with LE already exists (80 port is reserved), can not create proxy", domain, prxy.Port)
		}
	} else if protocol == HTTP && port == 80 {
		proxies, err = db.FindProxies(HTTPS, domain, 0)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
		for _, prxy := range proxies {
			//find proxies with redirected 80 port
			checkState(!prxy.Redirect80Port,
				"Proxy to https://%s:%d with port 80 redirection already exists, can not create proxy", domain, prxy.Port)
			//find LE proxies with the same domain
			checkState(!prxy.IsLE(),
				"Proxy to https://%s:%d with LE already exists (80 port is reserved), can not create proxy", domain, prxy.Port)
		}
	}

	//make optional flags consistent
	if protocol == HTTP || protocol == TCP || protocol == UDP {
		redirect80Port = false
		sslBackend = false
		certPath = ""
	} else if protocol == HTTPS && port == 80 && redirect80Port {
		redirect80Port = false
	}

	//save proxy
	proxy = &db.Proxy{
		Protocol:       protocol,
		Domain:         domain,
		Port:           port,
		Tag:            tag,
		CertPath:       certPath,
		Redirect80Port: redirect80Port,
		LoadBalancing:  loadBalancing,
		SslBackend:     sslBackend,
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

	var err error = nil
	var lock lockfile.Lockfile
	for lock, err = common.LockFile("port", "server"); err != nil; lock, err = common.LockFile("port", "server") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	proxy, err := db.FindProxyByTag(tag)
	log.Check(log.ErrorLevel, "Getting proxy from db", err)
	checkNotNil(proxy, "Proxy not found by tag %s", tag)

	proxiedServers, err := db.FindProxiedServers(tag, socket)
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)
	checkState(len(proxiedServers) == 0, "Proxied server already exists")

	checkArgument(isValidSocket(socket), "Server socket is not valid")

	if proxy.Port == 8443 || proxy.Port == 8444 || proxy.Port == 8086 {
		//check that server is management container
		checkArgument("10.10.10.1:"+strconv.Itoa(proxy.Port) == socket, "Reserved system port")
	}

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

	if len(proxiedServers) > 0 {
		//create config
		createConfig(proxy, proxiedServers)
	} else {
		if creating {
			//Install certificates for https
			if proxy.Protocol == HTTPS {
				if proxy.IsLE() {
					installLECert(proxy)
				} else {
					installSelfSignedCert(proxy)
				}
			}
			//return since we don't apply config for newly created proxy without added servers, no need to reload nginx
			return
		} else {
			removeConfig(*proxy)
		}
	}

	reloadNginx()
}

func installLECert(proxy *db.Proxy) {
	makeDir(path.Join(letsEncryptWebRootDir, proxy.Domain))
	//1) create http config with LE section
	generateLEConfig(proxy)
	//2) reload nginx
	reloadNginx()
	//3) run certbot
	obtainLECerts(proxy)
}

func obtainLECerts(proxy *db.Proxy) {
	args := []string{"certonly", "--config-dir", letsEncryptDir,
		"--email", "hostmaster@subutai.io", "--agree-tos", "--webroot",
		"--webroot-path", path.Join(letsEncryptWebRootDir, proxy.Domain),
		"-d", proxy.Domain, "-n"}
	if config.Agent.LeStaging {
		args = append(args, "--staging")
	}
	err := exec2.Exec("certbot", args...)
	log.Check(log.ErrorLevel, "Obtaining LE certs", err)
}

func removeCert(proxy *db.Proxy) {
	certDir := path.Join(selfSignedCertsDir, proxy.Domain+"-"+strconv.Itoa(proxy.Port))
	if proxy.IsLE() {
		//LE certs
		certDir = path.Join(letsEncryptCertsDir, proxy.Domain)
	}
	log.Check(log.ErrorLevel, "Removing certs", fs.DeleteDir(certDir))
}

func installSelfSignedCert(proxy *db.Proxy) {
	certDir := path.Join(selfSignedCertsDir, proxy.Domain+"-"+strconv.Itoa(proxy.Port))
	makeDir(certDir)
	crt, key := util.ParsePem(proxy.CertPath)
	log.Check(log.ErrorLevel, "Writing certificate", ioutil.WriteFile(path.Join(certDir, "cert.pem"), crt, 0644))
	log.Check(log.ErrorLevel, "Writing key", ioutil.WriteFile(path.Join(certDir, "privkey.pem"), key, 0644))
}

func generateLEConfig(proxy *db.Proxy) {
	//remove stale temporary nginx config files
	//todo remove later
	fs.RemoveFilesWildcard(path.Join(nginxInc, HTTP, "http-80-*.tmp.conf"))

	effectiveConfig := webConfig
	effectiveConfig = strings.Replace(effectiveConfig, "{well-known}", letsEncryptWellKnownSection, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{protocol}", HTTP, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{port}", strconv.Itoa(80), -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{domain}", proxy.Domain, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{servers}", "    server localhost:81;", -1)

	//remove other placeholders
	r := regexp.MustCompile("{\\S+}")
	effectiveConfig = r.ReplaceAllString(effectiveConfig, "")

	log.Check(log.ErrorLevel, "Writing nginx config", ioutil.WriteFile(path.Join(nginxInc, HTTPS, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"), []byte(effectiveConfig), 0744))
}

func createConfig(proxy *db.Proxy, servers []db.ProxiedServer) {
	cfg := ""

	if proxy.Protocol == HTTPS || proxy.Protocol == HTTP {
		cfg = createHttpHttpsConfig(proxy, servers)
	} else {
		cfg = createTcpUdpConfig(proxy, servers)
	}

	log.Check(log.ErrorLevel, "Writing nginx config", ioutil.WriteFile(path.Join(nginxInc, proxy.Protocol, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"), []byte(cfg), 0744))
}

func createTcpUdpConfig(proxy *db.Proxy, servers []db.ProxiedServer) string {
	//place-holders: {protocol}, {port}, {load-balancing}, {servers},
	effectiveConfig := strings.Replace(streamConfig, "{protocol}", proxy.Protocol, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{port}", strconv.Itoa(proxy.Port), -1)

	//load balancing
	loadBalancing := ""
	switch proxy.LoadBalancing {
	case "rr":
		//no-op
	case "sticky":
		loadBalancing = "ip_hash;"
	case "lcon":
		loadBalancing = "least_conn;"

	}
	effectiveConfig = strings.Replace(effectiveConfig, "{load-balancing}", loadBalancing, -1)

	//servers
	serversConfig := ""
	for i := 0; i < len(servers); i++ {
		serversConfig += "    server " + servers[i].Socket + ";\n"
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{servers}", serversConfig, -1)

	//udp
	if proxy.Protocol == UDP {
		effectiveConfig = strings.Replace(effectiveConfig, "{udp}", "udp", -1)
	} else {
		effectiveConfig = strings.Replace(effectiveConfig, "{udp}", "", -1)
	}

	return effectiveConfig
}

func createHttpHttpsConfig(proxy *db.Proxy, servers []db.ProxiedServer) string {
	//place-holders: {protocol}, {port}, {domain}, {load-balancing}, {servers}, {ssl},{ssl-backend}
	effectiveConfig := webConfig
	if proxy.IsLE() {
		effectiveConfig = strings.Replace(effectiveConfig, "{well-known}", letsEncryptWellKnownSection, -1)
	} else {
		effectiveConfig = strings.Replace(effectiveConfig, "{well-known}", "", -1)
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{protocol}", proxy.Protocol, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{port}", strconv.Itoa(proxy.Port), -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{domain}", proxy.Domain, -1)

	if proxy.Redirect80Port || proxy.IsLE() {
		effectiveConfig += strings.Replace(strings.Replace(redirect80Section, "{domain}", proxy.Domain, -1),
			"{port}", strconv.Itoa(proxy.Port), -1)
	}

	//load balancing
	loadBalancing := ""
	switch proxy.LoadBalancing {
	case "rr":
		//no-op
	case "sticky":
		loadBalancing = "ip_hash;"
	case "lcon":
		loadBalancing = "least_conn;"

	}
	effectiveConfig = strings.Replace(effectiveConfig, "{load-balancing}", loadBalancing, -1)

	//servers
	serversConfig := ""
	for i := 0; i < len(servers); i++ {
		serversConfig += "    server " + servers[i].Socket + ";\n"
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{servers}", serversConfig, -1)

	//ssl
	sslConfig := ""
	if proxy.Protocol == HTTPS {
		if proxy.IsLE() {
			//adjust path to LE cert
			certDir := figureOutDomainFolderName(proxy.Domain)
			sslConfig = strings.Replace(letsEncryptSslDirectives, "{domain}", certDir, -1)
		} else {
			certDir := proxy.Domain + "-" + strconv.Itoa(proxy.Port)
			sslConfig = strings.Replace(selfSignedSslDirectives, "{domain}", certDir, -1)
		}
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{ssl}", sslConfig, -1)

	sslBackend := ""
	if proxy.SslBackend {
		sslBackend = "s"
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{ssl-backend}", sslBackend, -1)

	return effectiveConfig
}

//workaround for https://github.com/certbot/certbot/issues/2128
func figureOutDomainFolderName(domain string) string {
	var validCertDirName = regexp.MustCompile(fmt.Sprintf("^%s(-\\d\\d\\d\\d)?$", domain))

	files, err := ioutil.ReadDir(letsEncryptCertsDir)
	log.Check(log.ErrorLevel, "Reading certificate directory", err)

	//collect all matching directory names
	var res []string
	for _, f := range files {
		if f.IsDir() && ( validCertDirName.MatchString(f.Name())) {
			res = append(res, filepath.Join(f.Name()))
		}
	}

	//sort
	sort.Strings(res)

	//reverse
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = res[j], res[i]
	}

	checkState(len(res) > 0, "Certificates for domain %s not found", domain)

	//since certbot does not generate certificates if they already exist, we assume that lexicographically last one is the dir
	return res[0]
}

func removeConfig(proxy db.Proxy) {
	//remove tmp config just in case
	//todo remove later
	fs.DeleteFile(path.Join(nginxInc, HTTP, "http-80-"+proxy.Domain+".tmp.conf"))
	//remove config
	err := fs.DeleteFile(path.Join(nginxInc, proxy.Protocol, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"))
	if !os.IsNotExist(err) {
		log.Check(log.ErrorLevel, "Removing nginx config", err)
	}
}

func deleteProxy(proxy *db.Proxy) {
	//remove cfg file
	removeConfig(*proxy)

	if proxy.Protocol == HTTPS {
		//remove certificates
		removeCert(proxy)
	}

	proxiedServers, err := db.FindProxiedServers(proxy.Tag, "")
	log.Check(log.ErrorLevel, "Getting proxied servers from db", err)

	//remove proxied servers from db
	for _, server := range proxiedServers {
		log.Check(log.ErrorLevel, "Removing proxied server from db", db.RemoveProxiedServer(&server))
	}

	//remove proxy from db
	log.Check(log.ErrorLevel, "Removing proxy from db", db.RemoveProxy(proxy))
}

func reloadNginx() {
	out, err := exec.Command("service", "subutai-nginx", "reload").CombinedOutput()
	log.Check(log.FatalLevel, "Reloading nginx "+string(out), err)
}

//utilities

func isValidSocket(socket string) bool {
	if addr := strings.Split(socket, ":"); len(addr) == 2 {
		if _, err := net.ResolveIPAddr("ip4", addr[0]); err == nil {
			if port, err := strconv.Atoi(addr[1]); err == nil && port < 65536 {
				return true
			}
		}
	}
	return false
}

func makeDir(path string) {
	if !fs.FileExists(path) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			log.Error("Failed to create directory " + path)
		}
	}
}
