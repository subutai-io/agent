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
	debugFlag = app.Flag("debug", "Set log level to DEBUG").Bool()

	//daemon command
	daemonCmd = app.Command("daemon", "Run subutai agent daemon")

	//subutai list command
	listCmd              = app.Command("list", "List containers/templates")
	listName             = listCmd.Arg("name", "container/template name").String()
	listContainers       = listCmd.Flag("containers", "list containers").Short('c').Bool()
	listTemplates        = listCmd.Flag("templates", "list templates").Short('t').Bool()
	listContainerDetails = listCmd.Flag("info", "list containers info").Short('i').Bool()
	listParents          = listCmd.Flag("parents", "list parents").Short('p').Bool()

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
	importCmd  = app.Command("import", "Import Subutai template")
	importName = importCmd.Arg("template", "template name/path to template archive").Required().String()
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
	//e.g. subutai hostname rh rh2, subutai hostname con foo foo2
	hostnameCmd           = app.Command("hostname", "Set host/container hostname")
	hostnameRh            = hostnameCmd.Command("rh", "Set RH hostname")
	hostnameRhNewHostname = hostnameRh.Arg("hostname", "new hostname").Required().String()

	hostnameContainer            = hostnameCmd.Command("con", "Set container hostname").Alias("container")
	hostnameContainerName        = hostnameContainer.Arg("container", "container name").Required().String()
	hostnameContainerNewHostname = hostnameContainer.Arg("hostname", "new hostname").Required().String()

	//map command
	//todo think of more explicit design
	//e.g. subutai map list, subutai map add .., subutai map del ..
	mapCmd            = app.Command("map", "Map ports")
	mapProtocol       = mapCmd.Arg("protocol", "http, https, tcp or udp").String()
	mapInternalSocket = mapCmd.Flag("internal", "internal socket").Short('i').String()
	mapExternalSocket = mapCmd.Flag("external", "external socket").Short('e').String()
	mapDomain         = mapCmd.Flag("domain", "domain name").Short('d').String()
	mapCert           = mapCmd.Flag("cert", "https certificate").Short('c').String()
	mapPolicy         = mapCmd.Flag("policy", "balancing policy").Short('p').String()
	mapRemove         = mapCmd.Flag("remove", "remove mapping").Short('r').Bool()
	mapSslBackend     = mapCmd.Flag("sslbackend", "use ssl backend in https upstream").Bool()
	mapList           = mapCmd.Flag("list", "list mapped ports").Short('l').Bool()

	//metrics command
	metricsCmd   = app.Command("metrics", "Print host/container metrics")
	metricsHost  = metricsCmd.Arg("name", "host/container name").Required().String()
	metricsStart = metricsCmd.Flag("start", "metrics start time 'yyyy-mm-dd hh:mi:ss'").Short('s').Required().String()
	metricsEnd   = metricsCmd.Flag("end", "metrics end time 'yyyy-mm-dd hh:mi:ss'").Short('e').Required().String()

	//proxy command
	//todo think of more explicit design
	//e.g. subutai proxy host add, subutai proxy domain check
	proxyCmd = app.Command("proxy", "Subutai reverse proxy")

	//proxy add command
	proxyAddCmd    = proxyCmd.Command("add", "Add reverse proxy component")
	proxyAddVlan   = proxyAddCmd.Arg("vlan", "environment vlan").Required().String()
	proxyAddDomain = proxyAddCmd.Flag("domain", "environment domain").Short('d').String()
	proxyAddHost   = proxyAddCmd.Flag("host", "container IP").Short('h').String()
	proxyAddCert   = proxyAddCmd.Flag("file", "certificate in PEM format").Short('f').String()
	proxyAddPolicy = proxyAddCmd.Flag("policy", "load balance policy (rr|lb|hash)").Short('p').String()

	//proxy del command
	proxyDelCmd    = proxyCmd.Command("del", "Remove reverse proxy component").Alias("rm")
	proxyDelVlan   = proxyDelCmd.Arg("vlan", "environment vlan").Required().String()
	proxyDelDomain = proxyDelCmd.Flag("domain", "remove environment domain").Short('d').Bool()
	proxyDelHost   = proxyDelCmd.Flag("host", "container IP").Short('h').String()

	//proxy check command
	proxyCheckCmd    = proxyCmd.Command("check", "Check existing domain/host")
	proxyCheckVlan   = proxyCheckCmd.Arg("vlan", "environment vlan").Required().String()
	proxyCheckDomain = proxyCheckCmd.Flag("domain", "check environment domain").Short('d').Bool()
	proxyCheckHost   = proxyCheckCmd.Flag("host", "container IP").Short('h').String()

	//todo improve, remove threshold param since alerts are not used
	//todo think of more explicit design
	//use subutai quota set ram foo 123
	//subutai quota get network foo
	//quota command
	quotaCmd       = app.Command("quota", "Manage container quotas")
	quotaContainer = quotaCmd.Arg("container", "container name").Required().String()
	quotaResource  = quotaCmd.Arg("resource", "resource type (cpu, cpuset, ram, disk, network)").Required().String()
	quotaLimit     = quotaCmd.Flag("set", "limit (% for cpu, # for cpuset, b for network, mb for ram, gb for disk )").Short('s').String()
	quotaThreshold = quotaCmd.Flag("threshold", "for internal usage").Hidden().Short('t').String()

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
	tunnelDelSocket = tunnelDelCmd.Arg("del socket", "socket in form ip[:port]").Required().String()
	//tunnel list command
	tunnelListCmd = tunnelCmd.Command("list", "List ssh tunnels").Alias("ls")
	//tunnel check command
	tunnelCheckCmd = tunnelCmd.Command("check", "for internal usage").Hidden()

	//todo think of more explicit design
	//e.g. subutai vxlan add, subutai vxlan del
	//vxlan command
	//todo change Console side to use either long flags with double dash or new short flags
	vxlanCmd            = app.Command("vxlan", "Manage vxlan tunnels")
	vxlanCreate         = vxlanCmd.Flag("create", "tunnel name").Short('c').String()
	vxlanCreateRemoteIp = vxlanCmd.Flag("remoteip", "remote ip").Short('r').String()
	vxlanCreateVni      = vxlanCmd.Flag("vni", "environment vni").Short('n').String()
	vxlanCreateVlan     = vxlanCmd.Flag("vlan", "environment vlan").Short('l').String()

	vxlanDelete = vxlanCmd.Flag("delete", "tunnel name").Short('d').String()

	vxlanList = vxlanCmd.Flag("list", "list tunnels").Bool()

	//batch command
	batchCmd  = app.Command("batch", "Execute a batch of commands")
	batchJson = batchCmd.Arg("commands", "batch of commands in JSON").Required().String()
)

func init() {
	app.Version(version)
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

	case listCmd.FullCommand():
		//todo LxcList should return result that is printed here , not inside LxcList
		//todo separeate into diff methods
		cli.LxcList(*listName, *listContainers, *listTemplates, *listContainerDetails, *listParents)
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
	case mapCmd.FullCommand():

		if *mapList {
			for _, v := range cli.GetMapList(*mapProtocol) {
				fmt.Println(v)
			}
			break
		} else if *mapProtocol != "" {
			if (*mapRemove && *mapExternalSocket != "") ||
				(!*mapRemove && *mapInternalSocket != "") {
				//todo separeate into diff methods
				cli.MapPort(*mapProtocol, *mapInternalSocket, *mapExternalSocket, *mapPolicy, *mapDomain, *mapCert, *mapRemove, *mapSslBackend)
				break
			}
		}
		app.Usage([]string{"map"})
	case metricsCmd.FullCommand():
		fmt.Println(cli.GetHostMetrics(*metricsHost, *metricsStart, *metricsEnd))
	case proxyAddCmd.FullCommand():
		cli.ProxyAdd(*proxyAddVlan, *proxyAddDomain, *proxyAddHost, *proxyAddPolicy, *proxyAddCert)
	case proxyDelCmd.FullCommand():
		cli.ProxyDel(*proxyDelVlan, *proxyDelHost, *proxyDelDomain)
	case proxyCheckCmd.FullCommand():
		cli.ProxyCheck(*proxyCheckVlan, *proxyCheckHost, *proxyCheckDomain)
	case quotaCmd.FullCommand():
		cli.LxcQuota(*quotaContainer, *quotaResource, *quotaLimit, *quotaThreshold)
	case startCmd.FullCommand():
		cli.LxcStart(*startCmdContainer)
	case stopCmd.FullCommand():
		cli.LxcStop(*stopCmdContainer)
	case restartCmd.FullCommand():
		cli.LxcRestart(*restartCmdContainer)
	case updateCmd.FullCommand():
		cli.Update(*updateCmdComponent, *updateCheck)
	case tunnelAddCmd.FullCommand():
		cli.TunAdd(*tunneAddSocket, *tunnelAddTimeout)
	case tunnelDelCmd.FullCommand():
		cli.TunDel(*tunnelDelSocket)
	case tunnelCheckCmd.FullCommand():
		cli.TunCheck()
	case tunnelListCmd.FullCommand():
		for _, tun := range cli.GetTunnels() {
			fmt.Printf("%s\t%s\t%s\n", tun.Remote, tun.Local, tun.Ttl)
		}

	case vxlanCmd.FullCommand():
		//todo separeate into diff methods
		cli.VxlanTunnel(*vxlanCreate, *vxlanDelete, *vxlanCreateRemoteIp, *vxlanCreateVlan, *vxlanCreateVni, *vxlanList)
	case batchCmd.FullCommand():
		cli.Batch(*batchJson)
	}

}
