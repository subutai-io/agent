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
	"gopkg.in/alecthomas/kingpin.v2"
	"fmt"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/agent/vars"
)

var version = "unknown"

func init() {
	if os.Getuid() != 0 {
		log.Error("Please run as root")
	}

	gpg.EnsureGPGVersion()

}

var (
	app       = kingpin.New("subutai", "Subutai Agent")
	debugFlag = app.Flag("debug", "Set log level to DEBUG").Short('d').Bool()

	//daemon command
	daemonCmd = app.Command("daemon", "Run subutai agent daemon")

	//subutai list command
	/*
	subutai list templates
	subutai list containers
	subutai list all
	subutai list info
	subutai list containers -n foo
	subutai list all -p
	 */
	listCmd               = app.Command("list", "List containers/templates").Alias("ls")
	listContainers        = listCmd.Command("containers", "List containers").Alias("c")
	listTemplates         = listCmd.Command("templates", "List templates").Alias("t")
	listAll               = listCmd.Command("all", "List all").Alias("a")
	listContainersDetails = listCmd.Command("info", "List containers info").Alias("i")
	listName              = listCmd.Flag("name", "container/template name").Short('n').String()
	listParents           = listCmd.Flag("parents", "list parents").Short('p').Bool()

	//attach command
	/*
	subutai attach foo
	subutai attach foo "ping localhost"
	*/
	attachCmd     = app.Command("attach", "Attach to Subutai container")
	attachName    = attachCmd.Arg("name", "running container name").Required().String()
	attachCommand = attachCmd.Arg("command", "ad-hoc command to execute").String()

	//clone command
	/*
	subutai clone master foo [-e {env-id} -n {net-settings} -s {secret}]
	*/
	cloneCmd       = app.Command("clone", "Create Subutai container")
	cloneTemplate  = cloneCmd.Arg("template", "source template").Required().String()
	cloneContainer = cloneCmd.Arg("container", "container name").Required().String()
	cloneEnvId     = cloneCmd.Flag("environment", "id of container environment").Short('e').String()
	cloneNetwork   = cloneCmd.Flag("network", "container network settings in form 'ip/mask vlan'").Short('n').String()
	cloneSecret    = cloneCmd.Flag("secret", "console secret").Short('s').String()

	//cleanup command
	/*
	subutai cleanup 123
	*/
	cleanupCmd  = app.Command("cleanup", "Cleanup environment")
	cleanupVlan = cleanupCmd.Arg("vlan", "environment vlan").Required().String()

	//prune templates command
	/*
	subutai prune
	*/
	pruneCmd = app.Command("prune", "Prune templates with no child containers")

	//destroy command
	/*
	subutai destroy foo
	*/
	destroyCmd  = app.Command("destroy", "Destroy Subutai container/template").Alias("rm").Alias("del")
	destroyName = destroyCmd.Arg("name", "container/template name").Required().String()

	//export command
	/*
	subutai export foo -t {token} [-n {template-name} -s tiny -r 1.0.0 --local]
	*/
	exportCmd       = app.Command("export", "Export container as a template")
	exportContainer = exportCmd.Arg("container", "source container").Required().String()
	exportToken     = exportCmd.Flag("token", "CDN token").Required().Short('t').String()
	exportName      = exportCmd.Flag("name", "template name").Short('n').String()
	exportSize      = exportCmd.Flag("size", "template preferred size").Short('s').String()
	exportLocal     = exportCmd.Flag("local", "export template to local cache").Short('l').Bool()
	exportVersion   = exportCmd.Flag("ver", "template version").Short('r').String()

	//import command
	/*
	subutai import debian-stretch

	#special case for management container:
	subutai import management -s {secret}
	*/
	importCmd    = app.Command("import", "Import Subutai template")
	importName   = importCmd.Arg("template", "template name/path to template archive").Required().String()
	importSecret = importCmd.Flag("secret", "console secret").Short('s').String()

	//info command
	infoCmd = app.Command("info", "System information")
	/*
	#RH id
	subutai info id

	#container id
	subutai info id foo
	*/
	infoIdCmd       = infoCmd.Command("id", "host/container id")
	infoIdContainer = infoIdCmd.Arg("container", "container name").String()
	//subutai info system
	infoSystemCmd = infoCmd.Command("system", "host info").Alias("sys")
	//subutai info os
	infoOsCmd = infoCmd.Command("os", "host os")
	//subutai info ip
	infoIpCmd = infoCmd.Command("ipaddr", "host ip address").Alias("ip")
	//subutai info ports
	infoPortsCmd = infoCmd.Command("ports", "host used ports").Alias("p")
	//subutai info du foo
	infoDUCmd       = infoCmd.Command("du", "container disk usage")
	infoDUContainer = infoDUCmd.Arg("container", "container name").Required().String()
	//subutai info qu foo
	infoQuotaCmd       = infoCmd.Command("qu", "container quota usage")
	infoQuotaContainer = infoQuotaCmd.Arg("container", "container name").Required().String()

	//hostname command
	//TODO add hostname read commands e.g. subutai hostname rh, subutai hostname con foo [no-console-change]
	/*
	subutai hostname rh new-rh-hostname
	subutai hostname container foo new-container-hostname
	*/
	hostnameCmd           = app.Command("hostname", "Set host/container hostname")
	hostnameRh            = hostnameCmd.Command("rh", "Set RH hostname")
	hostnameRhNewHostname = hostnameRh.Arg("hostname", "new hostname").Required().String()

	hostnameContainer            = hostnameCmd.Command("con", "Set container hostname").Alias("container")
	hostnameContainerName        = hostnameContainer.Arg("container", "container name").Required().String()
	hostnameContainerNewHostname = hostnameContainer.Arg("hostname", "new hostname").Required().String()

	//map command
	//e.g. subutai map list, subutai map add .., subutai map del ..
	/*
	subutai map add ...
	*/
	mapCmd               = app.Command("map", "Map ports")
	mapAddCmd            = mapCmd.Command("add", "Add port mapping")
	mapAddProtocol       = mapAddCmd.Flag("protocol", "http, https, tcp or udp").Short('p').Required().String()
	mapAddInternalSocket = mapAddCmd.Flag("internal", "internal socket").Short('i').Required().String()
	mapAddExternalSocket = mapAddCmd.Flag("external", "external socket").Short('e').String()
	mapAddDomain         = mapAddCmd.Flag("domain", "domain name").Short('n').String()
	mapAddCert           = mapAddCmd.Flag("cert", "https certificate").Short('c').String()
	mapAddPolicy         = mapAddCmd.Flag("policy", "load balancing policy (round_robin|hash|ip_hash|least_time)").Short('b').String()
	mapAddSslBackend     = mapAddCmd.Flag("sslbackend", "use ssl backend in https upstream").Bool()

	/*
	subutai map rm tcp ...
	*/
	mapRemoveCmd            = mapCmd.Command("rm", "Remove port mapping").Alias("del")
	mapRemoveProtocol       = mapRemoveCmd.Flag("protocol", "http, https, tcp or udp").Short('p').Required().String()
	mapRemoveExternalSocket = mapRemoveCmd.Flag("external", "external socket").Short('e').Required().String()
	mapRemoveInternalSocket = mapRemoveCmd.Flag("internal", "internal socket").Short('i').String()
	mapRemoveDomain         = mapRemoveCmd.Flag("domain", "domain name").Short('n').String()

	/*
	subutai map list
	subutai map list tcp
	*/
	mapList         = mapCmd.Command("list", "list mapped ports").Alias("ls")
	mapListProtocol = mapList.Flag("protocol", "http, https, tcp or udp").Short('p').String()

	//metrics command
	//subutai metrics -s "2018-08-17 02:26:11" -e "2018-08-17 03:26:11"
	metricsCmd   = app.Command("metrics", "Print host/container metrics")
	metricsHost  = metricsCmd.Arg("name", "host/container name").Required().String()
	metricsStart = metricsCmd.Flag("start", "metrics start time 'yyyy-mm-dd hh:mi:ss'").Short('s').Required().String()
	metricsEnd   = metricsCmd.Flag("end", "metrics end time 'yyyy-mm-dd hh:mi:ss'").Short('e').Required().String()

	//proxy command
	proxyCmd       = app.Command("proxy", "Subutai reverse proxy")
	proxyDomainCmd = proxyCmd.Command("domain", "Manage vlan-domain mappings").Alias("dom")
	proxyHostCmd   = proxyCmd.Command("host", "Manage domain hosts")

	//proxy dom add 123 test.com ...
	proxyDomainAddCmd    = proxyDomainCmd.Command("add", "Add vlan-domain mapping")
	proxyDomainAddVlan   = proxyDomainAddCmd.Arg("vlan", "environment vlan").Required().String()
	proxyDomainAddDomain = proxyDomainAddCmd.Arg("domain", "environment domain").Required().String()
	proxyDomainAddCert   = proxyDomainAddCmd.Flag("file", "certificate in PEM format").Short('f').String()
	proxyDomainAddPolicy = proxyDomainAddCmd.Flag("policy", "load balance policy (rr|lb|hash)").Short('b').String()

	//proxy dom del 123
	proxyDomainDelCmd  = proxyDomainCmd.Command("del", "Remove vlan-domain mapping").Alias("rm")
	proxyDomainDelVlan = proxyDomainDelCmd.Arg("vlan", "environment vlan").Required().String()

	//proxy dom check 123
	proxyDomainCheckCmd  = proxyDomainCmd.Command("check", "Check vlan-domain mapping")
	proxyDomainCheckVlan = proxyDomainCheckCmd.Arg("vlan", "environment vlan").Required().String()

	//proxy host add 123 {container ip[:port]}
	proxyHostAddCmd  = proxyHostCmd.Command("add", "Add host to domain")
	proxyHostAddVlan = proxyHostAddCmd.Arg("vlan", "environment vlan").Required().String()
	proxyHostAddHost = proxyHostAddCmd.Arg("host", "container ip[:port]").Required().String()

	//proxy host del 123 {container ip[:port]}
	proxyHostDelCmd  = proxyHostCmd.Command("del", "Remove host from domain").Alias("rm")
	proxyHostDelVlan = proxyHostDelCmd.Arg("vlan", "environment vlan").Required().String()
	proxyHostDelHost = proxyHostDelCmd.Arg("host", "container ip[:port]").Required().String()

	//proxy host check {vlan} {ip} command
	proxyHostCheckCmd  = proxyHostCmd.Command("check", "Check host in domain")
	proxyHostCheckVlan = proxyHostCheckCmd.Arg("vlan", "environment vlan").Required().String()
	proxyHostCheckHost = proxyHostCheckCmd.Arg("host", "container ip[:port]").Required().String()

	//quota command
	quotaCmd    = app.Command("quota", "Manage container quotas")
	quotaGetCmd = quotaCmd.Command("get", "Print container resource quota")
	quotaSetCmd = quotaCmd.Command("set", "Set container resource quota")

	//subutai quota get -c foo -r cpu
	quotaGetResource = quotaGetCmd.Flag("resource", "resource type (cpu, cpuset, ram, disk, network)").
		Short('r').Required().String()
	quotaGetContainer = quotaGetCmd.Flag("container", "container name").Short('c').Required().String()

	//subutai quota set -c foo -r cpu 123
	quotaSetResource = quotaSetCmd.Flag("resource", "resource type (cpu, cpuset, ram, disk, network)").
		Short('r').Required().String()
	quotaSetContainer = quotaSetCmd.Flag("container", "container name").Short('c').Required().String()
	quotaSetLimit     = quotaSetCmd.Arg("limit", "limit (% for cpu, # for cpuset, b for network, mb for ram, gb for disk )").Required().String()

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
	//subutai update rh
	//subutai update management -c
	updateCmd          = app.Command("update", "Update peer components")
	updateCmdComponent = updateCmd.Arg("component", "component to update (rh, management)").Required().String()
	updateCheck        = updateCmd.Flag("check", "check for updates without installation").Short('c').Bool()

	//tunnel command
	tunnelCmd = app.Command("tunnel", "Manage ssh tunnels")
	//tunnel add ip[:port] [ttl]
	tunnelAddCmd           = tunnelCmd.Command("add", "Create ssh tunnel")
	tunneAddSocket         = tunnelAddCmd.Arg("socket", "socket in form ip[:port]").Required().String()
	tunnelAddTimeout       = tunnelAddCmd.Arg("ttl", "ttl of tunnel (if ttl missing, tunnel is permanent)").String()
	tunnelAddHumanFriendly = tunnelAddCmd.Flag("ssh", "generate ssh connection string").Short('s').Bool()
	//tunnel del ip[:port]
	tunnelDelCmd    = tunnelCmd.Command("del", "Delete ssh tunnel").Alias("rm")
	tunnelDelSocket = tunnelDelCmd.Arg("socket", "socket in form ip[:port]").Required().String()
	//tunnel list
	tunnelListCmd = tunnelCmd.Command("list", "List ssh tunnels").Alias("ls")
	//tunnel check
	tunnelCheckCmd = tunnelCmd.Command("check", "for internal usage").Hidden()

	//vxlan command
	vxlanCmd = app.Command("vxlan", "Manage vxlan tunnels")
	//vxlan add command
	vxlanAddCmd      = vxlanCmd.Command("add", "Add vxlan tunnel")
	vxlanAddName     = vxlanAddCmd.Arg("name", "tunnel name").Required().String()
	vxlanAddRemoteIp = vxlanAddCmd.Flag("remoteip", "remote ip").Required().Short('r').String()
	vxlanAddVni      = vxlanAddCmd.Flag("vni", "environment vni").Required().Short('n').String()
	vxlanAddVlan     = vxlanAddCmd.Flag("vlan", "environment vlan").Required().Short('l').String()
	//vxlan del {tunnel-name}
	vxlanDelCmd  = vxlanCmd.Command("del", "Delete vxlan tunnel").Alias("rm")
	vxlanDelName = vxlanDelCmd.Arg("name", "tunnel name").Required().String()
	//vxlan list
	vxlanListCmd = vxlanCmd.Command("list", "List vxlan tunnels").Alias("ls")

	//batch command
	batchCmd  = app.Command("batch", "Execute a batch of commands")
	batchJson = batchCmd.Arg("commands", "batch of commands in JSON").Required().String()
)

func init() {
	app.Version(version)
	app.HelpFlag.Short('h')
	app.VersionFlag.Hidden().Short('v')

	vars.Version = version
}

func main() {

	input := kingpin.MustParse(app.Parse(os.Args[1:]))

	if *debugFlag {
		log.Level(log.DebugLevel)
	}

	vars.IsDaemon = input == daemonCmd.FullCommand()

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
		fmt.Println(cli.GetFingerprint(*infoIdContainer))
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
	case quotaGetCmd.FullCommand():
		cli.LxcQuota(*quotaGetContainer, *quotaGetResource, "", "")
	case quotaSetCmd.FullCommand():
		cli.LxcQuota(*quotaSetContainer, *quotaSetResource, *quotaSetLimit, "")
	case startCmd.FullCommand():
		cli.LxcStart(*startCmdContainer)
	case stopCmd.FullCommand():
		cli.LxcStop(*stopCmdContainer)
	case restartCmd.FullCommand():
		cli.LxcRestart(*restartCmdContainer)
	case updateCmd.FullCommand():
		cli.Update(*updateCmdComponent, *updateCheck)
	case tunnelAddCmd.FullCommand():
		cli.AddSshTunnel(*tunneAddSocket, *tunnelAddTimeout, *tunnelAddHumanFriendly)
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
