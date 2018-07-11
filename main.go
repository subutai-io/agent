// Subutai binary is consist of two parts: Agent and CLI
//
// Both packages placed in relevant directories. Detailed explanation can be found in github Wiki page: https://github.com/subutai-io/snap/wiki
package main

import (
	"os"

	"github.com/subutai-io/agent/agent"
	"github.com/subutai-io/agent/cli"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"

	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/exec"
	"strings"
	"github.com/subutai-io/agent/db"
	"gopkg.in/alecthomas/kingpin.v2"
	"fmt"
	"github.com/subutai-io/agent/lib/net"
)

var version = "unknown"

func init() {
	if os.Getuid() != 0 {
		log.Error("Please run as root")
	}

	checkGPG()
}

//todo move to GPG package
func checkGPG() {
	out, err := exec.Execute("gpg1", "--version")
	if err != nil {
		out, err = exec.Execute("gpg", "--version")

		if err != nil {
			log.Fatal("GPG not found " + out)
		} else {
			lines := strings.Split(out, "\n")
			if len(lines) > 0 && strings.HasPrefix(lines[0], "gpg (GnuPG) ") {
				version := strings.TrimSpace(strings.TrimPrefix(lines[0], "gpg (GnuPG)"))
				if strings.HasPrefix(version, "1.4") {
					gpg.GPG = "gpg"
				} else {
					log.Fatal("GPG version " + version + " is not compatible with subutai")
				}
			} else {
				log.Fatal("Failed to determine GPG version " + out)
			}
		}
	} else {
		lines := strings.Split(out, "\n")
		if len(lines) > 0 && strings.HasPrefix(lines[0], "gpg (GnuPG) ") {
			version := strings.TrimSpace(strings.TrimPrefix(lines[0], "gpg (GnuPG)"))
			if strings.HasPrefix(version, "1.4") {
				gpg.GPG = "gpg1"
			} else {
				log.Fatal("GPG version " + version + " is not compatible with subutai")
			}
		} else {
			log.Fatal("Failed to determine GPG version " + out)
		}
	}
}

//todo move to discovery package
func loadManagementIp() {
	if len(strings.TrimSpace(config.Management.Host)) == 0 {
		ip, err := db.INSTANCE.DiscoveryLoad()
		if !log.Check(log.WarnLevel, "Loading discovered ip from db", err) {
			config.Management.Host = ip
		}
	}
}

var (
	app       = kingpin.New("subutai", "Subutai Agent")
	debugFlag = app.Flag("debug", "Set log level to DEBUG").Short('d').Bool()

	//daemon command
	daemonCmd = app.Command("daemon", "Run subutai agent daemon")

	//subutai list command
	listCmd               = app.Command("list", "List containers/templates").Alias("ls")
	listContainers        = listCmd.Command("containers", "List containers").Alias("c")
	listTemplates         = listCmd.Command("templates", "List templates").Alias("t")
	listAll               = listCmd.Command("all", "List all").Alias("a")
	listContainersDetails = listCmd.Command("info", "List containers info").Alias("i")
	listName              = listCmd.Flag("name", "container/template name").Short('n').String()
	listParents           = listCmd.Flag("parents", "list parents").Short('p').Bool()

	//attach command
	attachCmd     = app.Command("attach", "Attach to Subutai container")
	attachName    = attachCmd.Arg("name", "running container name").Required().String()
	attachCommand = attachCmd.Arg("command", "ad-hoc command to execute").String()

	//clone command
	cloneCmd       = app.Command("clone", "Create Subutai container")
	cloneTemplate  = cloneCmd.Arg("template", "source template").Required().String()
	cloneContainer = cloneCmd.Arg("container", "container name").Required().String()
	cloneEnvId     = cloneCmd.Flag("environment", "id of container environment").Short('e').String()
	cloneNetwork   = cloneCmd.Flag("network", "container network settings in form 'ip/mask vlan'").Short('n').String()
	cloneSecret    = cloneCmd.Flag("secret", "console secret").Short('s').String()

	//cleanup command
	cleanupCmd  = app.Command("cleanup", "Cleanup environment")
	cleanupVlan = cleanupCmd.Arg("vlan", "environment vlan").Required().String()

	//prune templates command
	pruneCmd = app.Command("prune", "Prune templates with no child containers")

	//destroy command
	destroyCmd  = app.Command("destroy", "Destroy Subutai container/template").Alias("rm").Alias("del")
	destroyName = destroyCmd.Arg("name", "container/template name").Required().String()

	//export command
	exportCmd       = app.Command("export", "Export container as a template")
	exportContainer = exportCmd.Arg("container", "source container").Required().String()
	exportToken     = exportCmd.Flag("token", "CDN token").Required().Short('t').String()
	exportName      = exportCmd.Flag("name", "template name").Short('n').String()
	exportSize      = exportCmd.Flag("size", "template preferred size").Short('s').String()
	exportLocal     = exportCmd.Flag("local", "export template to local cache").Short('l').Bool()
	exportVersion   = exportCmd.Flag("ver", "template version").Short('r').String()

	//import command
	importCmd    = app.Command("import", "Import Subutai template")
	importName   = importCmd.Arg("template", "template name/path to template archive").Required().String()
	importSecret = importCmd.Flag("secret", "console secret").Short('s').String()

	//info command
	infoCmd            = app.Command("info", "System information")
	infoIdCmd          = infoCmd.Command("id", "host id")
	infoSystemCmd      = infoCmd.Command("system", "host info").Alias("sys")
	infoOsCmd          = infoCmd.Command("os", "host os")
	infoIpCmd          = infoCmd.Command("ipaddr", "host ip address").Alias("ip")
	infoPortsCmd       = infoCmd.Command("ports", "host used ports").Alias("p")
	infoDUCmd          = infoCmd.Command("du", "container disk usage")
	infoDUContainer    = infoDUCmd.Arg("container", "container name").Required().String()
	infoQuotaCmd       = infoCmd.Command("qu", "container quota usage")
	infoQuotaContainer = infoQuotaCmd.Arg("container", "container name").Required().String()

	//hostname command
	hostnameCmd           = app.Command("hostname", "Set host/container hostname")
	hostnameRh            = hostnameCmd.Command("rh", "Set RH hostname")
	hostnameRhNewHostname = hostnameRh.Arg("hostname", "new hostname").Required().String()

	hostnameContainer            = hostnameCmd.Command("con", "Set container hostname").Alias("container")
	hostnameContainerName        = hostnameContainer.Arg("container", "container name").Required().String()
	hostnameContainerNewHostname = hostnameContainer.Arg("hostname", "new hostname").Required().String()

	//map command
	//e.g. subutai map list, subutai map add .., subutai map del ..
	mapCmd               = app.Command("map", "Map ports")
	mapAddCmd            = mapCmd.Command("add", "Add port mapping")
	mapAddProtocol       = mapAddCmd.Arg("protocol", "http, https, tcp or udp").Required().String()
	mapAddInternalSocket = mapAddCmd.Flag("internal", "internal socket").Short('i').Required().String()
	mapAddExternalSocket = mapAddCmd.Flag("external", "external socket").Short('e').String()
	mapAddDomain         = mapAddCmd.Flag("domain", "domain name").Short('n').String()
	mapAddCert           = mapAddCmd.Flag("cert", "https certificate").Short('c').String()
	mapAddPolicy         = mapAddCmd.Flag("policy", "balancing policy").Short('p').String()
	mapAddSslBackend     = mapAddCmd.Flag("sslbackend", "use ssl backend in https upstream").Bool()

	mapRemoveCmd            = mapCmd.Command("rm", "Remove port mapping").Alias("del")
	mapRemoveProtocol       = mapRemoveCmd.Arg("protocol", "http, https, tcp or udp").Required().String()
	mapRemoveExternalSocket = mapRemoveCmd.Flag("external", "external socket").Short('e').Required().String()
	mapRemoveInternalSocket = mapRemoveCmd.Flag("internal", "internal socket").Short('i').String()
	mapRemoveDomain         = mapRemoveCmd.Flag("domain", "domain name").Short('n').String()

	mapList         = mapCmd.Command("list", "list mapped ports").Alias("ls")
	mapListProtocol = mapList.Arg("protocol", "http, https, tcp or udp").String()

	//metrics command
	metricsCmd   = app.Command("metrics", "Print host/container metrics")
	metricsHost  = metricsCmd.Arg("name", "host/container name").Required().String()
	metricsStart = metricsCmd.Flag("start", "metrics start time 'yyyy-mm-dd hh:mi:ss'").Short('s').Required().String()
	metricsEnd   = metricsCmd.Flag("end", "metrics end time 'yyyy-mm-dd hh:mi:ss'").Short('e').Required().String()

	//proxy command
	proxyCmd       = app.Command("proxy", "Subutai reverse proxy")
	proxyDomainCmd = proxyCmd.Command("domain", "Manage vlan-domain mappings").Alias("dom")
	proxyHostCmd   = proxyCmd.Command("host", "Manage domain hosts")

	//proxy dom add command
	proxyDomainAddCmd    = proxyDomainCmd.Command("add", "Add vlan-domain mapping")
	proxyDomainAddVlan   = proxyDomainAddCmd.Arg("vlan", "environment vlan").Required().String()
	proxyDomainAddDomain = proxyDomainAddCmd.Arg("domain", "environment domain").Required().String()
	proxyDomainAddCert   = proxyDomainAddCmd.Flag("file", "certificate in PEM format").Short('f').String()
	proxyDomainAddPolicy = proxyDomainAddCmd.Flag("policy", "load balance policy (rr|lb|hash)").Short('p').String()

	//proxy dom del {vlan} command
	proxyDomainDelCmd  = proxyDomainCmd.Command("del", "Remove vlan-domain mapping").Alias("rm")
	proxyDomainDelVlan = proxyDomainDelCmd.Arg("vlan", "environment vlan").Required().String()

	//proxy dom check {vlan} command
	proxyDomainCheckCmd  = proxyDomainCmd.Command("check", "Check vlan-domain mapping")
	proxyDomainCheckVlan = proxyDomainCheckCmd.Arg("vlan", "environment vlan").Required().String()

	//proxy host add {vlan} {ip} command
	proxyHostAddCmd  = proxyHostCmd.Command("add", "Add host to domain")
	proxyHostAddVlan = proxyHostAddCmd.Arg("vlan", "environment vlan").Required().String()
	proxyHostAddHost = proxyHostAddCmd.Arg("host", "container ip[:port]").Required().String()

	//proxy host del {vlan} {ip} command
	proxyHostDelCmd  = proxyHostCmd.Command("del", "Remove host from domain").Alias("rm")
	proxyHostDelVlan = proxyHostDelCmd.Arg("vlan", "environment vlan").Required().String()
	proxyHostDelHost = proxyHostDelCmd.Arg("host", "container ip[:port]").Required().String()

	//proxy host check {vlan} {ip} command
	proxyHostCheckCmd  = proxyHostCmd.Command("check", "Check host in domain")
	proxyHostCheckVlan = proxyHostCheckCmd.Arg("vlan", "environment vlan").Required().String()
	proxyHostCheckHost = proxyHostCheckCmd.Arg("host", "container ip[:port]").Required().String()

	//e.g. subutai quota ram foo -s 123
	//subutai quota cpu foo
	//quota command
	quotaCmd       = app.Command("quota", "Manage container quotas")
	quotaResource  = quotaCmd.Arg("resource", "resource type (cpu, cpuset, ram, disk, network)").Required().String()
	quotaContainer = quotaCmd.Arg("container", "container name").Required().String()
	quotaLimit     = quotaCmd.Flag("set", "limit (% for cpu, # for cpuset, b for network, mb for ram, gb for disk )").Short('s').String()

	//start command
	startCmd          = app.Command("start", "Start Subutai container")
	startCmdContainer = startCmd.Arg("name", "container name").Required().String()

	//stop command
	stopCmd          = app.Command("stop", "Stop Subutai container")
	stopCmdContainer = stopCmd.Arg("name", "container name").Required().String()

	//restart command
	restartCmd          = app.Command("restart", "Restart Subutai container")
	restartCmdContainer = restartCmd.Arg("name", "container name").Required().String()

	//update command
	updateCmd          = app.Command("update", "Update peer components")
	updateCmdComponent = updateCmd.Arg("component", "component to update (rh, management)").Required().String()
	updateCheck        = updateCmd.Flag("check", "check for updates without installation").Short('c').Bool()

	//tunnel command
	tunnelCmd = app.Command("tunnel", "Manage ssh tunnels")
	//tunnel add command
	tunnelAddCmd     = tunnelCmd.Command("add", "Create ssh tunnel")
	tunneAddSocket   = tunnelAddCmd.Arg("socket", "socket in form ip[:port]").Required().String()
	tunnelAddTimeout = tunnelAddCmd.Arg("ttl", "ttl of tunnel (if ttl missing, tunnel is permanent)").String()
	//tunnel del command
	tunnelDelCmd    = tunnelCmd.Command("del", "Delete ssh tunnel").Alias("rm")
	tunnelDelSocket = tunnelDelCmd.Arg("socket", "socket in form ip[:port]").Required().String()
	//tunnel list command
	tunnelListCmd = tunnelCmd.Command("list", "List ssh tunnels").Alias("ls")
	//tunnel check command
	tunnelCheckCmd = tunnelCmd.Command("check", "for internal usage").Hidden()

	//vxlan command
	vxlanCmd = app.Command("vxlan", "Manage vxlan tunnels")
	//vxlan add command
	vxlanAddCmd      = vxlanCmd.Command("add", "Add vxlan tunnel")
	vxlanAddName     = vxlanAddCmd.Arg("name", "tunnel name").Required().String()
	vxlanAddRemoteIp = vxlanAddCmd.Flag("remoteip", "remote ip").Required().Short('r').String()
	vxlanAddVni      = vxlanAddCmd.Flag("vni", "environment vni").Required().Short('n').String()
	vxlanAddVlan     = vxlanAddCmd.Flag("vlan", "environment vlan").Required().Short('l').String()
	//vxlan del command
	vxlanDelCmd  = vxlanCmd.Command("del", "Delete vxlan tunnel").Alias("rm")
	vxlanDelName = vxlanDelCmd.Arg("name", "tunnel name").Required().String()
	//vxlan list command
	vxlanListCmd = vxlanCmd.Command("list", "List vxlan tunnels").Alias("ls")

	//batch command
	batchCmd  = app.Command("batch", "Execute a batch of commands")
	batchJson = batchCmd.Arg("commands", "batch of commands in JSON").Required().String()
)

func init() {
	app.Version(version)
	app.HelpFlag.Short('h')
	app.VersionFlag.Hidden().Short('v')
}

func main() {

	input := kingpin.MustParse(app.Parse(os.Args[1:]))

	if *debugFlag {
		log.Level(log.DebugLevel)
	}

	if input != daemonCmd.FullCommand() {
		loadManagementIp()
	}

	switch input {

	case listContainers.FullCommand():
		cli.LxcList(*listName, true, false, false, *listParents)
	case listTemplates.FullCommand():
		cli.LxcList(*listName, false, true, false, *listParents)
	case listContainersDetails.FullCommand():
		cli.LxcList(*listName, false, false, true, *listParents)
	case listAll.FullCommand():
		cli.LxcList(*listName, true, true, false, *listParents)
	case daemonCmd.FullCommand():
		config.InitAgentDebug()
		agent.Start()
	case attachCmd.FullCommand():
		cli.LxcAttach(*attachName, *attachCommand)
	case cloneCmd.FullCommand():
		cli.LxcClone(*cloneTemplate, *cloneContainer, *cloneEnvId, *cloneNetwork, *cloneSecret)
	case cleanupCmd.FullCommand():
		cli.LxcDestroy(*cleanupVlan, true, false)
	case pruneCmd.FullCommand():
		cli.Prune()
	case destroyCmd.FullCommand():
		cli.LxcDestroy(*destroyName, false, false)
	case exportCmd.FullCommand():
		cli.LxcExport(*exportContainer, *exportName, *exportVersion, *exportSize, *exportToken, *exportLocal)
	case importCmd.FullCommand():
		cli.LxcImport(*importName, *importSecret)
	case infoIdCmd.FullCommand():
		fmt.Println(cli.GetFingerprint())
	case infoSystemCmd.FullCommand():
		fmt.Println(cli.GetSystemInfo())
	case infoOsCmd.FullCommand():
		fmt.Println(cli.GetOsName())
	case infoIpCmd.FullCommand():
		fmt.Println(net.GetIp())
	case infoPortsCmd.FullCommand():
		for k := range cli.GetUsedPorts() {
			fmt.Println(k)
		}
	case infoDUCmd.FullCommand():
		fmt.Println(cli.GetDiskUsage(*infoDUContainer))
	case infoQuotaCmd.FullCommand():
		fmt.Println(cli.GetContainerQuotaUsage(*infoQuotaContainer))
	case hostnameRh.FullCommand():
		cli.Hostname(*hostnameRhNewHostname)
	case hostnameContainer.FullCommand():
		cli.LxcHostname(*hostnameContainerName, *hostnameContainerNewHostname)

	case mapAddCmd.FullCommand():
		cli.AddPortMapping(*mapAddProtocol, *mapAddInternalSocket, *mapAddExternalSocket,
			*mapAddDomain, *mapAddPolicy, *mapAddCert, *mapAddSslBackend)
	case mapRemoveCmd.FullCommand():
		cli.RemovePortMapping(*mapRemoveProtocol, *mapRemoveInternalSocket, *mapRemoveExternalSocket,
			*mapRemoveDomain)

	case mapList.FullCommand():
		for _, v := range cli.GetPortMappings(*mapListProtocol) {
			fmt.Println(v)
		}
	case metricsCmd.FullCommand():
		fmt.Println(cli.GetHostMetrics(*metricsHost, *metricsStart, *metricsEnd))

	case proxyDomainAddCmd.FullCommand():
		cli.AddProxyDomain(*proxyDomainAddVlan, *proxyDomainAddDomain, *proxyDomainAddPolicy, *proxyDomainAddCert)
	case proxyDomainDelCmd.FullCommand():
		cli.DelProxyDomain(*proxyDomainDelVlan)
	case proxyDomainCheckCmd.FullCommand():
		domain := cli.GetProxyDomain(*proxyDomainCheckVlan)
		if domain != "" {
			fmt.Println(domain)
		} else {
			fmt.Println("No domain")
		}
	case proxyHostAddCmd.FullCommand():
		cli.AddProxyHost(*proxyHostAddVlan, *proxyHostAddHost)
	case proxyHostDelCmd.FullCommand():
		cli.DelProxyHost(*proxyHostDelVlan, *proxyHostDelHost)
	case proxyHostCheckCmd.FullCommand():
		res := cli.IsHostInDomain(*proxyHostCheckVlan, *proxyHostCheckHost)
		if res {
			log.Info("Host is in domain")
		} else {
			log.Info("Host is not in domain")
		}
	case quotaCmd.FullCommand():
		cli.LxcQuota(*quotaContainer, *quotaResource, *quotaLimit, "")
	case startCmd.FullCommand():
		cli.LxcStart(*startCmdContainer)
	case stopCmd.FullCommand():
		cli.LxcStop(*stopCmdContainer)
	case restartCmd.FullCommand():
		cli.LxcRestart(*restartCmdContainer)
	case updateCmd.FullCommand():
		cli.Update(*updateCmdComponent, *updateCheck)
	case tunnelAddCmd.FullCommand():
		cli.AddSshTunnel(*tunneAddSocket, *tunnelAddTimeout)
	case tunnelDelCmd.FullCommand():
		cli.DelSshTunnel(*tunnelDelSocket)
	case tunnelCheckCmd.FullCommand():
		cli.CheckSshTunnels()
	case tunnelListCmd.FullCommand():
		for _, tun := range cli.GetSshTunnels() {
			fmt.Printf("%s\t%s\t%s\n", tun.Remote, tun.Local, tun.Ttl)
		}

	case vxlanAddCmd.FullCommand():
		cli.AddVxlanTunnel(*vxlanAddName, *vxlanAddRemoteIp, *vxlanAddVlan, *vxlanAddVni)
	case vxlanDelCmd.FullCommand():
		cli.DelVxlanTunnel(*vxlanDelName)
	case vxlanListCmd.FullCommand():
		for _, tun := range cli.GetVxlanTunnels() {
			fmt.Println(tun.Name, tun.RemoteIp, tun.Vlan, tun.Vni)
		}

	case batchCmd.FullCommand():
		cli.Batch(*batchJson)
	}

}
