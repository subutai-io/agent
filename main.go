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
	debugFlag = app.Flag("debug", "Set log level to DEBUG").Short('d').Bool()

	//daemon command
	daemon = app.Command("daemon", "Run subutai agent daemon")

	//subutai list command
	list                     = app.Command("list", "List containers/templates")
	listName                 = list.Arg("name", "container/template name").String()
	listContainersFlag       = list.Flag("containers", "list containers").Short('c').Bool()
	listTemplatesFlag        = list.Flag("templates", "list templates").Short('t').Bool()
	listContainerDetailsFlag = list.Flag("info", "list containers info").Short('i').Bool()
	listParentsFlag          = list.Flag("parents", "list parents").Short('p').Bool()

	//attach command
	attach        = app.Command("attach", "Attach to Subutai container")
	attachName    = attach.Arg("name", "running container name").Required().String()
	attachCommand = attach.Arg("command", "ad-hoc command to execute").String()

	//clone command
	clone          = app.Command("clone", "Create Subutai container")
	cloneTemplate  = clone.Arg("template", "source template").Required().String()
	cloneContainer = clone.Arg("container", "container name").Required().String()
	cloneEnvId     = clone.Flag("environment", "id of container environment").Short('e').String()
	//todo change Console to use -n flag instead of -i
	cloneNetwork = clone.Flag("network", "container network settings in form 'ip/mask vlan'").Short('n').String()
	cloneSecret  = clone.Flag("secret", "console secret").Short('s').String()

	//cleanup command
	cleanup     = app.Command("cleanup", "Cleanup environment")
	cleanupVlan = cleanup.Arg("vlan", "environment vlan").Required().String()

	//prune templates command
	prune = app.Command("prune", "Prune templates with no child containers")

	//destroy command
	destroy     = app.Command("destroy", "Destroy Subutai container/template")
	destroyName = destroy.Arg("name", "container/template name").Required().String()

	//export command
	export          = app.Command("export", "Export container as a template")
	exportContainer = export.Arg("container", "source container").Required().String()
	exportToken     = export.Flag("token", "CDN token").Required().Short('t').String()
	exportName      = export.Flag("name", "template name").Short('n').String()
	exportSize      = export.Flag("size", "template preferred size").Short('s').String()
	exportLocal     = export.Flag("local", "export template to local cache").Short('l').Bool()
	//todo update Console side
	exportVersion = export.Flag("ver", "template version").Short('r').String()

	//import command
	importCmd  = app.Command("import", "Import Subutai template")
	importName = importCmd.Arg("template", "template name/path to template archive").Required().String()
	//todo refactor if template is path then assume it is local import, remove -l flag
	//todo update Console side
	importLocal  = importCmd.Flag("local", "import local template").Short('l').Bool()
	importSecret = importCmd.Flag("secret", "console secret").Short('s').String()

	//info command
	info          = app.Command("info", "System information")
	infoIdCmd     = info.Command("id", "resource host id")
	infoSystemCmd = info.Command("system", "resource host info").Alias("sys")
	infoOsCmd     = info.Command("os", "resource host os")
	infoIpCmd     = info.Command("ipaddr", "resource host ip address").Alias("ip")

	//
	//	Name: "info", Usage: "information about host system",
	//	Action: func(c *gcli.Context) error {
	//		cli.Info(c.Args().Get(0), c.Args().Get(1))
	//		return nil
	//	}}, {
)

func init() {
	app.Version(version)
	app.HelpFlag.Short('h')
	app.VersionFlag.Short('v')

}

func main() {

	input := kingpin.MustParse(app.Parse(os.Args[1:]))

	if *debugFlag {
		log.Level(log.DebugLevel)
	}

	if input != daemon.FullCommand() {
		loadManagementIp()
	}

	switch input {

	case list.FullCommand():
		cli.LxcList(*listName, *listContainersFlag, *listTemplatesFlag, *listContainerDetailsFlag, *listParentsFlag)
	case daemon.FullCommand():
		config.InitAgentDebug()
		agent.Start()
	case attach.FullCommand():
		cli.LxcAttach(*attachName, *attachCommand)
	case clone.FullCommand():
		cli.LxcClone(*cloneTemplate, *cloneContainer, *cloneEnvId, *cloneNetwork, *cloneSecret)
	case cleanup.FullCommand():
		cli.LxcDestroy(*cleanupVlan, true, false)
	case prune.FullCommand():
		cli.Prune()
	case destroy.FullCommand():
		cli.LxcDestroy(*destroyName, false, false)
	case export.FullCommand():
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
	}

	//
	//	Name: "hostname", Usage: "Set hostname of container or host",
	//	Action: func(c *gcli.Context) error {
	//		if c.Args().Get(0) == "" {
	//			gcli.ShowSubcommandHelp(c)
	//		} else if len(c.Args().Get(1)) != 0 {
	//			cli.LxcHostname(c.Args().Get(0), c.Args().Get(1))
	//		} else {
	//			cli.Hostname(c.Args().Get(0))
	//		}
	//		return nil
	//	}}, {
	//
	//
	//	Name: "map", Usage: "Subutai port mapping",
	//	Flags: []gcli.Flag{
	//		gcli.StringFlag{Name: "internal, i", Usage: "internal socket"},
	//		gcli.StringFlag{Name: "external, e", Usage: "RH port"},
	//		gcli.StringFlag{Name: "domain, d", Usage: "domain name"},
	//		gcli.StringFlag{Name: "cert, c", Usage: "https certificate"},
	//		gcli.StringFlag{Name: "policy, p", Usage: "balancing policy"},
	//		gcli.BoolFlag{Name: "list, l", Usage: "list mapped ports"},
	//		gcli.BoolFlag{Name: "remove, r", Usage: "remove map"},
	//		gcli.BoolFlag{Name: "sslbackend", Usage: "ssl backend in https upstream"},
	//	},
	//	Action: func(c *gcli.Context) error {
	//		if len(c.Args()) > 0 || c.NumFlags() > 0 {
	//			cli.MapPort(c.Args().Get(0), c.String("i"), c.String("e"), c.String("p"), c.String("d"), c.String("c"), c.Bool("l"), c.Bool("r"), c.Bool("sslbackend"))
	//		} else {
	//			gcli.ShowSubcommandHelp(c)
	//		}
	//		return nil
	//	}}, {
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
