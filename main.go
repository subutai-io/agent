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
	//todo change Console to use -n flag instead of -i
	cloneNetwork = cloneCmd.Flag("network", "container network settings in form 'ip/mask vlan'").Short('n').String()
	cloneSecret  = cloneCmd.Flag("secret", "console secret").Short('s').String()

	//cleanup command
	cleanupCmd  = app.Command("cleanup", "Cleanup environment")
	cleanupVlan = cleanupCmd.Arg("vlan", "environment vlan").Required().String()

	//prune templates command
	pruneCmd = app.Command("prune", "Prune templates with no child containers")

	//destroy command
	destroyCmd  = app.Command("destroy", "Destroy Subutai container/template")
	destroyName = destroyCmd.Arg("name", "container/template name").Required().String()

	//export command
	exportCmd       = app.Command("export", "Export container as a template")
	exportContainer = exportCmd.Arg("container", "source container").Required().String()
	exportToken     = exportCmd.Flag("token", "CDN token").Required().Short('t').String()
	exportName      = exportCmd.Flag("name", "template name").Short('n').String()
	exportSize      = exportCmd.Flag("size", "template preferred size").Short('s').String()
	exportLocal     = exportCmd.Flag("local", "export template to local cache").Short('l').Bool()
	//todo update Console side
	exportVersion = exportCmd.Flag("ver", "template version").Short('r').String()

	//import command
	importCmd  = app.Command("import", "Import Subutai template")
	importName = importCmd.Arg("template", "template name/path to template archive").Required().String()
	//todo refactor if template is path then assume it is local import, remove -l flag
	//todo update Console side
	importLocal  = importCmd.Flag("local", "import local template").Short('l').Bool()
	importSecret = importCmd.Flag("secret", "console secret").Short('s').String()

	//info command
	infoCmd         = app.Command("info", "System information")
	infoIdCmd       = infoCmd.Command("id", "host id")
	infoSystemCmd   = infoCmd.Command("system", "host info").Alias("sys")
	infoOsCmd       = infoCmd.Command("os", "host os")
	infoIpCmd       = infoCmd.Command("ipaddr", "host ip address").Alias("ip")
	infoPortsCmd    = infoCmd.Command("ports", "host used ports").Alias("p")
	infoDUCmd       = infoCmd.Command("du", "container disk usage")
	infoDUContainer = infoDUCmd.Arg("container", "container name").Required().String()
	//todo remove "subutai quota" usage on Console side
	infoQuotaCmd       = infoCmd.Command("qu", "container quota usage")
	infoQuotaContainer = infoQuotaCmd.Arg("container", "container name").Required().String()

	//hostname command
	//todo refactor Console side
	hostnameCmd         = app.Command("hostname", "Set host/container hostname")
	hostnameNewHostname = hostnameCmd.Arg("hostname", "new hostname").Required().String()
	hostnameContainer   = hostnameCmd.Arg("container", "container name").String()

	//map command
	mapCmd            = app.Command("map", "Map ports")
	mapProtocol       = mapCmd.Arg("protocol", "http, https, tcp or udp").String()
	mapInternalSocket = mapCmd.Flag("internal", "internal socket").Short('i').String()
	mapExternalSocket = mapCmd.Flag("external", "external socket").Short('e').String()
	mapDomain         = mapCmd.Flag("domain", "domain name").Short('d').String()
	mapCert           = mapCmd.Flag("cert", "https certificate").Short('c').String()
	mapPolicy         = mapCmd.Flag("policy", "balancing policy").Short('p').String()
	mapRemove         = mapCmd.Flag("remove", "remove mapping").Short('r').Bool()
	mapSslBackend     = mapCmd.Flag("sslbackend", "ssl backend in https upstream").Bool()
	mapList           = mapCmd.Flag("list", "list mapped ports").Short('l').Bool()
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

	case listCmd.FullCommand():
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
		cli.LxcImport(*importName, *importSecret, *importLocal)
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
	case hostnameCmd.FullCommand():
		if *hostnameContainer != "" {
			cli.LxcHostname(*hostnameContainer, *hostnameNewHostname)
		} else {
			cli.Hostname(*hostnameNewHostname)
		}
	case mapCmd.FullCommand():

		if *mapList {
			for _, v := range cli.GetMapList(*mapProtocol) {
				fmt.Println(v)
			}
			break
		} else if *mapProtocol != "" {
			if (*mapRemove && *mapExternalSocket != "") ||
				(!*mapRemove && *mapInternalSocket != "") {

				cli.MapPort(*mapProtocol, *mapInternalSocket, *mapExternalSocket, *mapPolicy, *mapDomain, *mapCert, *mapRemove, *mapSslBackend)
				break
			}
		}
		app.Usage([]string{"map"})
	}

	//
	//	Name: "metrics", Usage: "list Subutai container",
	//	Flags: []gcli.Flag{
	//		gcli.StringFlag{Name: "start, s", Usage: "start time"},
	//		gcli.StringFlag{Name: "end, e", Usage: "end time"}},
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) != "" {
	//			cli.HostMetrics(c.Args().Get(0), c.String("s"), c.String("e"))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
	//
	//	Name: "proxy", Usage: "Subutai reverse proxy",
	//	Subcommands: []gcli.Command{
	//		{
	//			Name:     "add",
	//			Usage:    "add reverse proxy component",
	//			HideHelp: true,
	//			Flags: []gcli.Flag{
	//				gcli.StringFlag{Name: "domain, d", Usage: "add domain to vlan"},
	//				gcli.StringFlag{Name: "host, h", Usage: "add host to domain on vlan"},
	//				gcli.StringFlag{Name: "policy, p", Usage: "set load balance policy (rr|lb|hash)"},
	//				gcli.StringFlag{Name: "file, f", Usage: "specify pem certificate file"}},
	//			Action: func(c *gcli.Context) error {
	//				cli.ProxyAdd(c.Args().Get(0), c.String("d"), c.String("h"), c.String("p"), c.String("f"))
	//				return nil
	//			},
	//		},
	//		{
	//			Name:     "del",
	//			Usage:    "del reverse proxy component",
	//			HideHelp: true,
	//			Flags: []gcli.Flag{
	//				gcli.BoolFlag{Name: "domain, d", Usage: "delete domain from vlan"},
	//				gcli.StringFlag{Name: "host, h", Usage: "delete host from domain on vlan"}},
	//			Action: func(c *gcli.Context) error {
	//				cli.ProxyDel(c.Args().Get(0), c.String("h"), c.Bool("d"))
	//				return nil
	//			},
	//		},
	//		{
	//			Name:     "check",
	//			Usage:    "check existing domain or host",
	//			HideHelp: true,
	//			Flags: []gcli.Flag{
	//				gcli.BoolFlag{Name: "domain, d", Usage: "check domains on vlan"},
	//				gcli.StringFlag{Name: "host, h", Usage: "check hosts on vlan"}},
	//			Action: func(c *gcli.Context) error {
	//				cli.ProxyCheck(c.Args().Get(0), c.String("h"), c.Bool("d"))
	//				return nil
	//			},
	//		},
	//	}}, {
	//
	//	Name: "quota", Usage: "set quotas for Subutai container",
	//	Flags: []gcli.Flag{
	//		gcli.StringFlag{Name: "set, s", Usage: "set quota for the specified resource type (cpu, cpuset, ram, disk, network)"},
	//		gcli.StringFlag{Name: "threshold, t", Usage: "set alert threshold"}},
	//	Action: func(c *gcli.Context) error {
	//		cli.LxcQuota(c.Args().Get(0), c.Args().Get(1), c.String("s"), c.String("t"))
	//		return nil
	//	}}, {
	//
	//	Name: "stats", Usage: "statistics from host",
	//	Action: func(c *gcli.Context) error {
	//		cli.Info(c.Args().Get(0), c.Args().Get(1))
	//		return nil
	//	}}, {
	//
	//	Name: "start", Usage: "start Subutai container",
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) != "" {
	//			cli.LxcStart(c.Args().Get(0))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
	//
	//	Name: "stop", Usage: "stop Subutai container",
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) != "" {
	//			cli.LxcStop(c.Args().Get(0))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
	//
	//	Name: "restart", Usage: "restart Subutai container",
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) != "" {
	//			cli.LxcRestart(c.Args().Get(0))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
	//
	//	Name: "tunnel", Usage: "SSH tunnel management",
	//	Subcommands: []gcli.Command{
	//		{
	//			Name:  "add",
	//			Usage: "add ssh tunnel",
	//			Flags: []gcli.Flag{
	//				gcli.BoolFlag{Name: "global, g", Usage: "create tunnel to global proxy"}},
	//			Action: func(c *gcli.Context) error {
	//				cli.TunAdd(c.Args().Get(0), c.Args().Get(1))
	//				return nil
	//			}}, {
	//			Name:  "del",
	//			Usage: "delete tunnel",
	//			Action: func(c *gcli.Context) error {
	//				cli.TunDel(c.Args().Get(0))
	//				return nil
	//			}}, {
	//			Name:  "list",
	//			Usage: "list active ssh tunnels",
	//			Action: func(c *gcli.Context) error {
	//				cli.TunList()
	//				return nil
	//			}}, {
	//			Name:  "check",
	//			Usage: "check active ssh tunnels",
	//			Action: func(c *gcli.Context) error {
	//				cli.TunCheck()
	//				return nil
	//			}},
	//	}}, {
	//
	//	Name: "update", Usage: "update Subutai management, container or Resource host",
	//	Flags: []gcli.Flag{
	//		gcli.BoolFlag{Name: "check, c", Usage: "check for updates without installation"}},
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) != "" {
	//			cli.Update(c.Args().Get(0), c.Bool("c"))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
	//
	//	Name: "vxlan", Usage: "VXLAN tunnels operation",
	//	Flags: []gcli.Flag{
	//		gcli.StringFlag{Name: "create, c", Usage: "create vxlan tunnel"},
	//		gcli.StringFlag{Name: "delete, d", Usage: "delete vxlan tunnel"},
	//		gcli.BoolFlag{Name: "list, l", Usage: "list vxlan tunnels"},
	//
	//		gcli.StringFlag{Name: "remoteip, r", Usage: "vxlan tunnel remote ip"},
	//		gcli.StringFlag{Name: "vlan, vl", Usage: "tunnel vlan"},
	//		gcli.StringFlag{Name: "vni, v", Usage: "vxlan tunnel vni"},
	//	},
	//	Action: func(c *gcli.Context) error {
	//		cli.VxlanTunnel(c.String("c"), c.String("d"), c.String("r"), c.String("vl"), c.String("v"), c.Bool("l"))
	//		return nil
	//	}},
	//}
	//

	//TODO implement or remove batch later
	//	Name: "batch", Usage: "batch commands execution",
	//	Flags: []gcli.Flag{
	//		gcli.StringFlag{Name: "json, j", Usage: "JSON string with commands"}},
	//	Action: func(c *gcli.Context) error {
	//		if c.String("j") != "" {
	//			cli.Batch(c.String("j"))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {

	// TODO remove
	//	Name: "config", Usage: "edit container config",
	//	Flags: []gcli.Flag{
	//		gcli.StringFlag{Name: "operation, o", Usage: "<add|del> operation"},
	//		gcli.StringFlag{Name: "key, k", Usage: "configuration key"},
	//		gcli.StringFlag{Name: "value, v", Usage: "configuration value"},
	//	},
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) != "" {
	//			cli.LxcConfig(c.Args().Get(0), c.String("o"), c.String("k"), c.String("v"))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
	//app.Run(os.Args)
}
