package cli

import (
	"strings"
	"github.com/subutai-io/agent/log"
	"fmt"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/config"
	"path"
	"os"
	"strconv"
	"io/ioutil"
	"regexp"
	exec2 "github.com/subutai-io/agent/lib/exec"
	"path/filepath"
	"sort"
	"github.com/subutai-io/agent/agent/util"
	"github.com/pkg/errors"
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
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection $http_connection;
    }

	#well-known
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
				Redirect80Port: false,
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
		var proxies []db.Proxy
		if v.Proxy.Protocol == UDP {
			proxies, _ = db.FindProxies(UDP, "", v.Proxy.Port)
		} else {
			tcpProxies, _ := db.FindProxies(TCP, "", v.Proxy.Port)
			httpProxies, _ := db.FindProxies(HTTP, "", v.Proxy.Port)
			httpsProxies, _ := db.FindProxies(HTTPS, "", v.Proxy.Port)

			proxies := append(tcpProxies, httpProxies...)
			proxies = append(proxies, httpsProxies...)
		}
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

func reloadNginx() error {
	out, err := exec2.Execute("service", "subutai-nginx", "reload")
	if err != nil {
		log.Warn("Error reloading nginx, ", err)
		return errors.New(out + ", " + err.Error())
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

func createHttpHttpsConfig(proxy *db.Proxy, servers []db.ProxiedServer) string {
	//place-holders: {protocol}, {port}, {domain}, {load-balancing}, {servers}, {ssl},{ssl-backend}
	effectiveConfig := webConfig

	//for http-80 proxy check if there is https proxy for the same domain with LE cert
	//if such poxy exists we need to add "well-known" section for LE cert renewal support
	if proxy.Protocol == HTTP && proxy.Port == 80 {
		proxies, err := db.FindProxies(HTTPS, proxy.Domain, 0)
		log.Check(log.ErrorLevel, "Checking proxy in db", err)
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

func makeDir(path string) {
	if !fs.FileExists(path) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			log.Error("Failed to create directory " + path)
		}
	}
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
