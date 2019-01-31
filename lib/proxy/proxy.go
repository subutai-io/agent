package proxy

import (
	"github.com/nightlyone/lockfile"
	"time"
	"strings"
	"github.com/subutai-io/agent/lib/gpg"
	"fmt"
	"os"
	"io/ioutil"
	"path/filepath"
	"sort"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/common"
	"github.com/subutai-io/agent/lib/net"
	"github.com/pkg/errors"
	"github.com/subutai-io/agent/lib/fs"
	"strconv"
	"path"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/exec"
	"github.com/subutai-io/agent/agent/util"
	"regexp"
)

//todo split this file into types, snippets,
//return descriptive errors

const HTTP = "http"
const HTTPS = "https"
const UDP = "udp"
const TCP = "tcp"

const TAGFORMAT = "%s-%d-%s"

var (
	nginxInc = path.Join(config.Agent.DataPrefix, "nginx/nginx-includes")
)

type ProxyNServers struct {
	Proxy   db.Proxy
	Servers []db.ProxiedServer
}

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

    {well-known}

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
//place-holders: {protocol}, {port}, {domain}, {load-balancing}, {servers}, {ssl}, {http2}
const webConfig = `
upstream {protocol}-{port}-{domain}{
    {load-balancing}

{servers}
}                                                                                                                                                                                       

server {
    listen {port} {http2};
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
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection $http_connection;
    }

	#well-known
	{well-known}
}

`

const lEConfig = `

server {
    listen 80;
    server_name {domain};

    {well-known}
}

`

//place-holders: {domain}
const letsEncryptSslDirectives = `
    ssl on;
    ssl_certificate /var/lib/subutai/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /var/lib/subutai/letsencrypt/live/{domain}/privkey.pem;
`

//place-holders: {domain}
const selfSignedSslDirectives = `
    ssl on;
    ssl_certificate /var/lib/subutai/web/ssl/{domain}/cert.pem;
    ssl_certificate_key /var/lib/subutai/web/ssl/{domain}/privkey.pem;
`

var SelfSignedCertsDir = path.Join(config.Agent.DataPrefix, "/web/ssl")
var letsEncryptDir = path.Join(config.Agent.DataPrefix, "/letsencrypt")
var letsEncryptWebRootDir = path.Join(letsEncryptDir, "/webroot")
var letsEncryptCertsDir = path.Join(letsEncryptDir, "/live")

func init() {
	makeDir(SelfSignedCertsDir)
	makeDir(letsEncryptDir)
	makeDir(letsEncryptWebRootDir)
	makeDir(letsEncryptCertsDir)

	makeDir(path.Join(nginxInc, HTTPS))
	makeDir(path.Join(nginxInc, HTTP))
	makeDir(path.Join(nginxInc, TCP))
	makeDir(path.Join(nginxInc, UDP))
}

func GetProxies(protocol string) ([]ProxyNServers, error) {
	var proxyNServers []ProxyNServers

	proxies, err := db.FindProxies(protocol, "", 0)
	if err != nil {
		return nil, err
	}

	for _, proxy := range proxies {
		proxiedServers, err := db.FindProxiedServers(proxy.Tag, "")
		if err != nil {
			return nil, err
		}

		proxyNServers = append(proxyNServers, ProxyNServers{Proxy: proxy, Servers: proxiedServers})
	}

	return proxyNServers, nil
}

func FindProxyByTag(tag string) (*db.Proxy, error) {
	return db.FindProxyByTag(tag)
}

func FindProxiedServers(tag, socket string) ([]db.ProxiedServer, error) {
	return db.FindProxiedServers(tag, socket);
}

//subutai prxy create -p https -n test.com -e 80 -t 123 [-b round_robin] [--redirect] [-c path/to/cert] [--sslbackend]
//subutai prxy create -p http -n test.com -e 80 -t 123 [-b round_robin]
func CreateProxy(protocol, domain, loadBalancing, tag string, port int, redirect80Port, sslBackend bool, certPath string, http2 bool) error {
	var err error = nil
	var lock lockfile.Lockfile
	for lock, err = common.LockFile("port", "proxy");
		err != nil; lock, err = common.LockFile("port", "proxy") {

		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	protocol = strings.ToLower(protocol)
	domain = strings.ToLower(domain)
	loadBalancing = strings.ToLower(loadBalancing)
	tag = strings.ToLower(tag)

	//check if protocol is https or https
	if !(protocol == HTTP || protocol == HTTPS || protocol == TCP || protocol == UDP) {
		return errors.New(fmt.Sprintf("Unsupported protocol %s", protocol))
	}

	//check if port is specified and valid
	if !(port == 80 || port == 443 || (port >= 1000 && port <= 65535)) {
		return errors.New(fmt.Sprintf("External port must be one of [80, 443, 1000-65535] "))
	}

	//check domain
	if protocol == HTTP || protocol == HTTPS {
		if domain == "" {
			return errors.New(fmt.Sprintf("Domain is required for http/https proxies"))
		}
	} else {
		//empty domain for tcp/udp
		domain = ""
	}

	if loadBalancing != "" {
		if !(loadBalancing == "rr" || loadBalancing == "lcon" ||
			loadBalancing == "sticky") {

			return errors.New(fmt.Sprintf("Balancing policy must be one of [rr,sticky,lcon]"))
		}
	}

	//default policy to round-robin
	if len(loadBalancing) == 0 {
		loadBalancing = "rr"
	}

	if protocol == HTTPS {
		//check if supplied certificate file exists
		if !(certPath == "" || fs.FileExists(certPath)) {
			return errors.New(fmt.Sprintf("Certificate file %s does not exist", certPath))
		}

		//check if supplied certificate file is valid
		if !(certPath == "" || gpg.ValidatePem(certPath)) {
			return errors.New(fmt.Sprintf("Certificate file %s is not valid", certPath))
		}
	}

	//check if tag is new
	proxy, err := db.FindProxyByTag(tag)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
	}
	if proxy != nil {
		return errors.New(fmt.Sprintf("Proxy with tag %s already exists", tag))
	}

	//verify that proxy with the same combination of protocol+domain+port does not exist
	proxies, err := db.FindProxies(protocol, domain, port)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
	}
	if len(proxies) > 0 {
		return errors.New(fmt.Sprintf(
			"Proxy with such combination of protocol, domain and port already exists"))
	}

	if protocol == TCP || protocol == UDP {
		//check port range
		if port < 1000 {
			return errors.New(fmt.Sprintf("For tcp/udp protocols port must be >= 1000"))
		}

		//check if port is not already reserved (udp can coexist with other protocols)
		if protocol == TCP {
			tcpProxies, err := db.FindProxies(TCP, "", port)
			if err != nil {
				return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
			}
			httpProxies, err := db.FindProxies(HTTP, "", port)
			if err != nil {
				return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
			}
			httpsProxies, err := db.FindProxies(HTTPS, "", port)
			if err != nil {
				return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
			}

			proxies := append(tcpProxies, httpProxies...)
			proxies = append(proxies, httpsProxies...)

			if len(proxies) > 0 {
				return errors.New(fmt.Sprintf("Proxy to %s://%s:%d already exists, can not create proxy",
					proxies[0].Protocol, proxies[0].Domain, port))
			}
		}

	} else {
		//HTTP/HTTPS
		//check if the same tcp port is not reserved
		//and check if the same http/https port and domain is not reserved
		tcpProxies, err := db.FindProxies(TCP, "", port)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}
		httpProxies, err := db.FindProxies(HTTP, domain, port)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}
		httpsProxies, err := db.FindProxies(HTTPS, domain, port)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}

		proxies := append(tcpProxies, httpProxies...)
		proxies = append(proxies, httpsProxies...)

		if len(proxies) > 0 {
			return errors.New(fmt.Sprintf("Proxy to %s://%s:%d already exists, can not create proxy",
				proxies[0].Protocol, proxies[0].Domain, port))
		}
	}

	//if redirection is requested (https only, otherwise ignored), check if port 80 for http+domain is not already reserved
	if protocol == HTTPS && redirect80Port {
		//check all http proxies with 80 port
		proxies, err := db.FindProxies(HTTP, domain, 80)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}
		if len(proxies) > 0 {
			return errors.New(fmt.Sprintf("Proxy to http://%s:80 already exists, can not redirect", domain))
		}

		//check https proxies with redirect to 80 port
		proxies, err = db.FindProxies(HTTPS, domain, 0)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}
		for _, prxy := range proxies {
			if prxy.Redirect80Port {
				return errors.New(fmt.Sprintf(
					"Proxy to https://%s:%d with port 80 redirection already exists, can not redirect",
					domain, prxy.Port))
			}
		}
	} else if protocol == HTTP && port == 80 {
		proxies, err = db.FindProxies(HTTPS, domain, 0)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}
		for _, prxy := range proxies {
			if prxy.Redirect80Port {
				return errors.New(fmt.Sprintf(
					"Proxy to https://%s:%d with port 80 redirection already exists, can not create proxy",
					domain, prxy.Port))
			}
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
	if !(protocol == HTTP || protocol == HTTPS) {
		http2 = false
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
		Http2:          http2,
	}

	err = db.SaveProxy(proxy)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving proxy to db: %s", err.Error()))
	}

	return applyConfig(tag, true)
}

func RemoveProxy(tag string) error {
	proxy, err := db.FindProxyByTag(tag)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
	}
	if proxy == nil {
		return errors.New(fmt.Sprintf("Proxy not found by tag %s", tag))
	}

	err = deleteProxy(proxy)
	if err != nil {
		return errors.New(fmt.Sprintf("Error deleting proxy from db: %s", err.Error()))
	}

	err = reloadNginx()
	if err != nil {
		return errors.New(fmt.Sprintf("Error reloading nginx: %s", err.Error()))
	}

	return nil
}

func AddProxiedServer(tag, socket string) error {

	var err error = nil
	var lock lockfile.Lockfile
	for lock, err = common.LockFile("port", "server");
		err != nil; lock, err = common.LockFile("port", "server") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	proxy, err := db.FindProxyByTag(tag)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
	}

	if proxy == nil {
		return errors.New(fmt.Sprintf("Proxy not found by tag %s", tag))
	}

	proxiedServers, err := db.FindProxiedServers(tag, socket)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up server in db: %s", err.Error()))
	}

	if len(proxiedServers) > 0 {
		return errors.New(fmt.Sprintf("Proxied server already exists"))
	}

	if !net.IsValidSocket(socket) {
		return errors.New(fmt.Sprintf("Server socket is not valid"))
	}

	if proxy.Port == 8443 || proxy.Port == 8444 || proxy.Port == 8086 {
		//check that server is management container
		if "10.10.10.1:"+strconv.Itoa(proxy.Port) != socket {
			return errors.New("Reserved system port")
		}
	}

	proxiedServer := &db.ProxiedServer{
		ProxyTag: tag,
		Socket:   socket,
	}

	err = db.SaveProxiedServer(proxiedServer)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving server to db: %s", err.Error()))
	}

	return applyConfig(tag, false)

}

func RemoveProxiedServer(tag, socket string) error {
	proxy, err := db.FindProxyByTag(tag)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
	}
	if proxy == nil {
		return errors.New(fmt.Sprintf("Proxy not found by tag %s", tag))
	}

	proxiedServers, err := db.FindProxiedServers(tag, socket)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up server in db: %s", err.Error()))
	}
	if len(proxiedServers) == 0 {
		return errors.New(fmt.Sprintf("Proxied server not found"))
	}

	err = db.RemoveProxiedServer(&proxiedServers[0])
	if err != nil {
		return errors.New(fmt.Sprintf("Error removing server from db: %s", err.Error()))
	}

	return applyConfig(tag, false)
}

func applyConfig(tag string, creating bool) error {
	proxy, err := db.FindProxyByTag(tag)
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
	}

	if proxy == nil {
		return errors.New(fmt.Sprintf("Proxy not found by tag %s", tag))
	}

	proxiedServers, err := db.FindProxiedServers(tag, "")
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up server in db: %s", err.Error()))
	}

	if len(proxiedServers) > 0 {
		//create config
		err = createConfig(proxy, proxiedServers)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating nginx config: %s", err.Error()))
		}
	} else {
		if creating {
			//Install certificates for https
			if proxy.Protocol == HTTPS {
				if proxy.IsLE() {
					err = installLECert(proxy)
				} else {
					err = installSelfSignedCert(proxy)
				}
				if err != nil {
					return errors.New(fmt.Sprintf("Error installing ccertificates: %s", err.Error()))
				}
			}
			//return since we don't apply config for newly created proxy without added servers, no need to reload nginx
			return nil
		} else {
			err = removeConfig(*proxy)
			if err != nil {
				return errors.New(fmt.Sprintf("Error removing nginx config: %s", err.Error()))
			}
		}
	}

	return reloadNginx()
}

func installLECert(proxy *db.Proxy) error {
	err := makeDir(path.Join(letsEncryptWebRootDir, proxy.Domain))
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating directory: %s", err.Error()))
	}
	//1) create http config with LE section
	err = generateLEConfig(proxy)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating LE nginx config: %s", err.Error()))
	}
	//2) reload nginx && run certbot
	err = reloadNginx()
	if err == nil {
		err = obtainLECerts(proxy)
	}
	if err != nil {
		//ignore errors
		//delete proxy in case of error during LE certificate obtainment
		deleteProxy(proxy)
		//remove self created LE config
		proxies, _ := db.FindProxies(HTTP, proxy.Domain, 80)
		if len(proxies) == 0 {
			er := fs.DeleteFile(path.Join(nginxInc, HTTP, proxy.Domain+"-80.conf"))
			if er != nil && !os.IsNotExist(er) {
				return errors.New(fmt.Sprintf("Error removing temporary LE nginx config: %s", er.Error()))
			}
		}
		return errors.New(fmt.Sprintf("Failed to create proxy: %s", err.Error()))
	}
	return nil
}

func obtainLECerts(proxy *db.Proxy) error {
	args := []string{"certonly", "--config-dir", letsEncryptDir,
		"--email", "hostmaster@subutai.io", "--agree-tos", "--webroot",
		"--webroot-path", path.Join(letsEncryptWebRootDir, proxy.Domain),
		"-d", proxy.Domain, "-n"}
	if config.Agent.LeStaging {
		args = append(args, "--staging")
	}

	out, err := exec.Execute("certbot", args...)
	if err != nil {
		return errors.New(fmt.Sprintf("Error obtaining LE certificate: %s", out+", "+err.Error()))
	}

	return nil
}

func reloadNginx() error {
	out, err := exec.Execute("service", "subutai-nginx", "reload")
	if err != nil {
		return errors.New(fmt.Sprintf("Error reloading nginx: %s", out+", "+err.Error()))
	}

	return nil
}

func removeCert(proxy *db.Proxy) error {
	certDir := path.Join(SelfSignedCertsDir, proxy.Domain+"-"+strconv.Itoa(proxy.Port))
	if proxy.IsLE() {
		//LE certs
		certDir = path.Join(letsEncryptCertsDir, proxy.Domain)
	}
	err := fs.DeleteDir(certDir)
	if err != nil && !os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("Error removing certs: %s", err))
	}

	return nil
}

func installSelfSignedCert(proxy *db.Proxy) error {
	certDir := path.Join(SelfSignedCertsDir, proxy.Domain+"-"+strconv.Itoa(proxy.Port))
	err := makeDir(certDir)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating directory: %s", err.Error()))
	}
	crt, key, err := util.ParsePem(proxy.CertPath)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing certificate: %s", err.Error()))
	}
	err = ioutil.WriteFile(path.Join(certDir, "cert.pem"), crt, 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving certificate: %s", err.Error()))
	}
	err = ioutil.WriteFile(path.Join(certDir, "privkey.pem"), key, 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving private key: %s", err.Error()))
	}
	return nil
}

//check if http-80 mapping already exists for this domain
//if exists then append well-known section to it
//otherwise create http-80 port config with well-known section
func generateLEConfig(proxy *db.Proxy) error {

	filePath := path.Join(nginxInc, HTTP, proxy.Domain+"-80.conf")
	var effectiveConfig string
	if fs.FileExists(filePath) {
		//append "well-known" section to existing http-80 mapping config
		read, err := ioutil.ReadFile(filePath)
		if err != nil {
			return errors.New(fmt.Sprintf("Error reading nginx config: %s", err.Error()))
		}
		effectiveConfig = string(read)
		//check if config already has well-known section defined
		if strings.Contains(effectiveConfig, ".well-known") {
			return nil
		}
		effectiveConfig = strings.Replace(effectiveConfig, "#well-known", letsEncryptWellKnownSection, -1)
	} else {
		//create nginx config with LE support
		effectiveConfig = lEConfig
		effectiveConfig = strings.Replace(effectiveConfig, "{well-known}", letsEncryptWellKnownSection, -1)
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{domain}", proxy.Domain, -1)
	err := ioutil.WriteFile(filePath, []byte(effectiveConfig), 0744)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving nginx config: %s", err.Error()))
	}
	return nil
}

func createConfig(proxy *db.Proxy, servers []db.ProxiedServer) error {
	cfg := ""
	var err error
	if proxy.Protocol == HTTPS || proxy.Protocol == HTTP {
		cfg, err = createHttpHttpsConfig(proxy, servers)
		if err != nil {
			return errors.New(fmt.Sprintf("Error composing http(s) nginx config: %s", err.Error()))
		}
	} else {
		cfg = createTcpUdpConfig(proxy, servers)
	}

	if proxy.IsLE() && proxy.Redirect80Port {
		//remove self created LE config if any in case there is no explicit http-80 mapping for this domain
		proxies, err := db.FindProxies(HTTP, proxy.Domain, 80)
		if err != nil {
			return errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))
		}

		if len(proxies) == 0 {
			err = fs.DeleteFile(path.Join(nginxInc, HTTP, proxy.Domain+"-80.conf"))
			if err != nil && !os.IsNotExist(err) {
				return errors.New(fmt.Sprintf("Error removing temporary LE nginx config: %s", err.Error()))
			}
		}
	}

	err = ioutil.WriteFile(path.Join(nginxInc, proxy.Protocol,
		proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"), []byte(cfg), 0744)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving nginx config: %s", err.Error()))
	}
	return nil
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

func createHttpHttpsConfig(proxy *db.Proxy, servers []db.ProxiedServer) (string, error) {
	//place-holders: {protocol}, {port}, {domain}, {load-balancing}, {servers}, {ssl}, {ssl-backend}, {http2}
	effectiveConfig := webConfig

	//for http-80 proxy check if there is https proxy for the same domain with LE cert
	//if such poxy exists we need to add "well-known" section for LE cert renewal support
	if proxy.Protocol == HTTP && proxy.Port == 80 {
		proxies, err := db.FindProxies(HTTPS, proxy.Domain, 0)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Error looking up proxy in db: %s", err.Error()))

		}
		for _, prxy := range proxies {
			if prxy.IsLE() && !prxy.Redirect80Port {
				effectiveConfig = strings.Replace(effectiveConfig, "{well-known}", letsEncryptWellKnownSection, -1)
				break
			}
		}
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{well-known}", "", -1)

	effectiveConfig = strings.Replace(effectiveConfig, "{protocol}", proxy.Protocol, -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{port}", strconv.Itoa(proxy.Port), -1)
	effectiveConfig = strings.Replace(effectiveConfig, "{domain}", proxy.Domain, -1)

	if proxy.Redirect80Port {
		redirect := redirect80Section
		if proxy.IsLE() {
			redirect = strings.Replace(redirect, "{well-known}", letsEncryptWellKnownSection, -1)
		} else {
			redirect = strings.Replace(redirect, "{well-known}", "", -1)
		}
		redirect = strings.Replace(strings.Replace(redirect, "{domain}", proxy.Domain, -1),
			"{port}", strconv.Itoa(proxy.Port), -1)
		effectiveConfig += redirect
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
			certDir, err := figureOutDomainFolderName(proxy.Domain)
			if err != nil {
				return "", errors.New(fmt.Sprintf("Error calculating LE domain folder: %s", err.Error()))
			}

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

	http2 := ""
	if proxy.Http2 {
		http2 = "http2"
	}
	effectiveConfig = strings.Replace(effectiveConfig, "{http2}", http2, -1)

	return effectiveConfig, nil
}

//workaround for https://github.com/certbot/certbot/issues/2128
func figureOutDomainFolderName(domain string) (string, error) {
	var validCertDirName = regexp.MustCompile(fmt.Sprintf("^%s(-\\d\\d\\d\\d)?$", domain))

	files, err := ioutil.ReadDir(letsEncryptCertsDir)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error reading directory: %s", err.Error()))
	}

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

	if len(res) == 0 {

		return "", errors.New(fmt.Sprintf("Certificates for domain %s not found", domain))
	}

	//since certbot does not generate certificates if they already exist, we assume that lexicographically last one is the dir
	return res[0], nil
}

func removeConfig(proxy db.Proxy) error {
	//remove config
	err := fs.DeleteFile(path.Join(nginxInc, proxy.Protocol, proxy.Domain+"-"+strconv.Itoa(proxy.Port)+".conf"))
	if err != nil && !os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("Removing nginx config: %s", err.Error()))
	}

	return nil
}

func deleteProxy(proxy *db.Proxy) error {
	//remove cfg file
	err := removeConfig(*proxy)

	if err != nil {
		return errors.New(fmt.Sprintf("Error removing nginx config: %s", err.Error()))
	}

	if proxy.Protocol == HTTPS {
		//remove certificates
		err = removeCert(proxy)
		if err != nil {
			return errors.New(fmt.Sprintf("Error removing certificates: %s", err.Error()))
		}

	}

	proxiedServers, err := db.FindProxiedServers(proxy.Tag, "")
	if err != nil {
		return errors.New(fmt.Sprintf("Error looking up server in db: %s", err.Error()))
	}
	//remove proxied servers from db
	for _, server := range proxiedServers {
		err = db.RemoveProxiedServer(&server)
		if err != nil {
			return errors.New(fmt.Sprintf("Error removing server from db: %s", err.Error()))
		}
	}

	//remove proxy from db
	err = db.RemoveProxy(proxy)
	if err != nil {
		return errors.New(fmt.Sprintf("Error removing proxy from db: %s", err.Error()))
	}

	return nil
}

//utilities

func makeDir(path string) error {
	if !fs.FileExists(path) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}
