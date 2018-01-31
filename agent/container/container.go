// Package container gathers basic information about containers needed by Subutai Agent
package container

import (
	"bufio"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"

	cont "github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"

	"gopkg.in/lxc/go-lxc.v2"
	"github.com/subutai-io/agent/db"
	"github.com/wunderlist/ttlcache"
	"time"
)

var (
	cache *ttlcache.Cache
)

// Container describes Subutai container with all required options for the Management server.
type Container struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Hostname   string        `json:"hostname"`
	Status     string        `json:"status,omitempty"`
	Arch       string        `json:"arch"`
	Interfaces []utils.Iface `json:"interfaces"`
	Parent     string        `json:"templateName,omitempty"`
	Vlan       string        `json:"vlan,omitempty"`
	EnvId      string        `json:"environmentId,omitempty"`
	Pk         string        `json:"publicKey,omitempty"`
	Quota      Quota         `json:"quota,omitempty"`
}

//Quota describes container quota value.
type Quota struct {
	CPU  int `json:"cpu,omitempty"`
	RAM  int `json:"ram,omitempty"`
	Disk int `json:"disk,omitempty"`
	Root int `json:"root,omitempty"`
	Home int `json:"home,omitempty"`
	Opt  int `json:"opt,omitempty"`
	Var  int `json:"var,omitempty"`
}

func init() {
	//initialize cache
	cache = ttlcache.NewCache(time.Minute * 30)
}

// Credentials returns information about IDs from container. This informations is user for command execution only.
func Credentials(name, container string) (uid int, gid int) {
	path := config.Agent.LxcPrefix + container + "/rootfs/etc/passwd"
	u, g := parsePasswd(path, name)
	uid, err := strconv.Atoi(u)
	log.Check(log.DebugLevel, "Parsing user UID from container", err)
	gid, err = strconv.Atoi(g)
	log.Check(log.DebugLevel, "Parsing user GID from container", err)
	return uid, gid
}

func parsePasswd(path, name string) (uid string, gid string) {
	file, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), name) {
			arr := strings.Split(scanner.Text(), ":")
			if len(arr) > 3 {
				return arr[2], arr[3]
			}
		}
	}
	return "", ""
}

// Active provides list of active Subutai containers.
func Active(details bool) []Container {
	contArr := []Container{}

	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	defer bolt.Close()

	for _, c := range cont.Containers() {
		hostname, err := ioutil.ReadFile(config.Agent.LxcPrefix + c + "/rootfs/etc/hostname")
		if err != nil {
			continue
		}
		configpath := config.Agent.LxcPrefix + c + "/config"

		meta := bolt.ContainerByName(c)

		vlan := meta["vlan"]
		envId := meta["environment"]
		ip := meta["ip"]

		container := Container{
			//ID:       gpg.GetFingerprint(c),
			//Arch: strings.ToUpper(cont.GetConfigItem(configpath, "lxc.arch")),
			//Parent: cont.GetConfigItem(configpath, "subutai.parent"),
			//Interfaces: interfaces(c, ""),
			Name:     c,
			Hostname: strings.TrimSpace(string(hostname)),
			Status:   cont.State(c),
			Vlan:     vlan,
			EnvId:    envId,
		}

		container.Interfaces = interfaces(c, ip)

		//cacheable properties>>>

		container.ID = getFromCacheOrCalculate(c+"_fingerprint", func() string {
			return gpg.GetFingerprint(c)
		})

		container.Arch = getFromCacheOrCalculate(c+"_arch", func() string {
			return strings.ToUpper(cont.GetConfigItem(configpath, "lxc.arch"))
		})

		container.Parent = getFromCacheOrCalculate(c+"_parent", func() string {
			return cont.GetConfigItem(configpath, "subutai.parent")
		})

		//<<<cacheable properties

		if details {
			container.Pk = gpg.GetContainerPk(c)
		}

		contArr = append(contArr, container)
	}
	return contArr
}

type calculate func() string

func getFromCacheOrCalculate(cacheKey string, calc calculate) string {
	value, exists := cache.Get(cacheKey)

	if exists {
		return value
	} else {
		value = calc()
		if value != "" {
			cache.Set(cacheKey, value)
		}
		return value
	}
}

//todo refactor to remove interfaces and just have ip field sent to Console
//this should be done together with Console changes
func interfaces(name string, staticIp string) []utils.Iface {

	iface := new(utils.Iface)

	iface.InterfaceName = "eth0"

	if staticIp != "" {
		iface.IP = staticIp
	} else {
		c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
		if err == nil {
			listip, err := c.IPAddress(iface.InterfaceName)
			if err == nil {
				iface.IP = strings.Join(listip, " ")
			}
		}
	}

	return []utils.Iface{*iface}
}
