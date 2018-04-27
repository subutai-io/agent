//Package container main function is to provide control interface for Subutai containers through go-lxc bindings and system-level libraries and executables
package container

import (
	"bufio"
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"

	"gopkg.in/lxc/go-lxc.v2"
	"path"
	"fmt"
	"crypto/rand"
)

// All returns list of all containers
func All() []string {
	return lxc.DefinedContainerNames(config.Agent.LxcPrefix)
}

// IsTemplate checks if Subutai container is template.
func IsTemplate(name string) bool {
	return fs.DatasetExists(name+"/rootfs") && fs.IsDatasetReadOnly(name+"/rootfs/")
}

func IsContainer(name string) bool {
	return fs.DatasetExists(name+"/rootfs") && !fs.IsDatasetReadOnly(name + "/rootfs/")
}

// Templates returns list of all templates
func Templates() (containers []string) {
	for _, name := range All() {
		if IsTemplate(name) {
			containers = append(containers, name)
		}
	}
	return
}

// Containers returns list of all containers
func Containers() (containers []string) {
	for _, name := range All() {
		if IsContainer(name) {
			containers = append(containers, name)
		}
	}
	return
}

// LxcInstanceExists checks if container or template exists
func LxcInstanceExists(name string) bool {
	for _, item := range All() {
		if name == item {
			return true
		}
	}
	return false
}

// State returns container state in human readable format.
func State(name string) (state string) {
	if c, err := lxc.NewContainer(name, config.Agent.LxcPrefix); err == nil {
		defer lxc.Release(c)
		return c.State().String()
	}
	return "UNKNOWN"
}

// SetApt configures APT configuration inside Subutai container.
func SetApt(name string) {
	root := GetParent(name)
	for parent := name; root != parent; root = GetParent(parent) {
		parent = root
	}
	if root != "master" {
		return
	}
	gateway := GetConfigItem(config.Agent.LxcPrefix+name+"/config", "lxc.network.ipv4.gateway")
	if len(gateway) == 0 {
		gateway = "10.10.10.254"
	}
	repo := []byte("deb http://" + gateway + "/apt/main trusty main restricted universe multiverse\n" +
		"deb http://" + gateway + "/apt/main trusty-updates main restricted universe multiverse\n" +
		"deb http://" + gateway + "/apt/security trusty-security main restricted universe multiverse\n")
	log.Check(log.DebugLevel, "Writing apt source repo list",
		ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/apt/sources.list", repo, 0644))

	// kurjun := []byte("deb [arch=amd64,all] http://" + config.Management.Host + ":8330/rest/kurjun/vapt trusty main contrib\n" +
	// 	"deb [arch=amd64,all] http://" + config.Cdn.Url + ":8330/kurjun/rest/deb trusty main contrib\n")
	kurjun := []byte("deb http://" + config.CDN.URL + ":8080/kurjun/rest/apt /\n")
	log.Check(log.DebugLevel, "Writing apt source kurjun list",
		ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/apt/sources.list.d/subutai-repo.list", kurjun, 0644))
}

// AddMetadata adds container information to database
func AddMetadata(name string, meta map[string]string) error {
	if !LxcInstanceExists(name) {
		return errors.New("Container does not exists")
	}
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	log.Check(log.WarnLevel, "Writing container data to database", bolt.ContainerAdd(name, meta))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
	return nil
}

// Start starts the Subutai container.
func Start(name string) error {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}
	defer lxc.Release(c)

	log.Check(log.DebugLevel, "Starting LXC container "+name, c.Start())
	if c.State().String() != "RUNNING" {
		return errors.New("Unable to start container " + name)
	}
	AddMetadata(name, map[string]string{"state": "RUNNING"})
	return nil
}

// Stop stops the Subutai container.
func Stop(name string, addMetadata bool) error {

	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}
	defer lxc.Release(c)

	log.Check(log.DebugLevel, "Stopping LXC container "+name, c.Stop())

	if c.State().String() != "STOPPED" {
		return errors.New("Unable to stop container " + name)
	}

	if addMetadata {
		AddMetadata(name, map[string]string{"state": "STOPPED"})
	}

	return nil
}

func Restart(name string) error {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}
	defer lxc.Release(c)

	if c.State().String() == "RUNNING" {
		err = c.Reboot()
	} else {
		err = c.Start()
	}

	log.Check(log.DebugLevel, "Restarting LXC container "+name, err)

	return err
}

// AttachExec executes a command inside Subutai container.
func AttachExec(name string, command []string, env ...[]string) (output []string, err error) {
	if !LxcInstanceExists(name) {
		return output, errors.New("Container does not exist")
	}

	container, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(container)
	}

	if container.State() != lxc.RUNNING || err != nil {
		return output, errors.New("Container is " + container.State().String())
	}

	bufR, bufW, err := os.Pipe()
	if err != nil {
		return output, errors.New("Failed to create OS pipe")
	}
	bufRErr, bufWErr, err := os.Pipe()
	if err != nil {
		return output, errors.New("Failed to create OS pipe")
	}

	options := lxc.AttachOptions{
		Namespaces: -1,
		UID:        0,
		GID:        0,
		StdoutFd:   bufW.Fd(),
		StderrFd:   bufWErr.Fd(),
	}
	if len(env) > 0 {
		options.Env = env[0]
	}

	_, err = container.RunCommand(command, options)
	log.Check(log.DebugLevel, "Executing command inside container", err)
	log.Check(log.DebugLevel, "Closing write buffer for stdout", bufW.Close())
	defer bufR.Close()
	log.Check(log.DebugLevel, "Closing write buffer for stderr", bufWErr.Close())
	defer bufRErr.Close()

	out := bufio.NewScanner(bufR)
	for out.Scan() {
		output = append(output, out.Text())
	}

	return output, nil
}

// Destroy deletes the Subutai container.
func DestroyContainer(name string) error {

	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}

	defer lxc.Release(c)

	if c.State() == lxc.RUNNING {
		if err = c.Stop(); log.Check(log.DebugLevel, "Stopping container", err) {
			return err
		}
	}

	log.Info("Destroying container " + name)

	log.Check(log.DebugLevel, "Destroying lxc", c.Destroy())

	if fs.DatasetExists(name) {
		fs.RemoveDataset(name, true)
	}

	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	log.Check(log.WarnLevel, "Deleting container metadata entry", bolt.ContainerDel(name))
	log.Check(log.WarnLevel, "Deleting uuid entry", bolt.DelUuidEntry(name))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	return nil
}

func DestroyTemplate(name string) {

	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	log.Check(log.ErrorLevel, "Creating container object", err)

	defer lxc.Release(c)

	//check just in case
	if c.State() == lxc.RUNNING {
		log.Check(log.ErrorLevel, "Stopping container", c.Stop())
	}

	log.Info("Destroying template " + name)

	log.Check(log.DebugLevel, "Destroying lxc", c.Destroy())

	if fs.DatasetExists(name) {
		fs.RemoveDataset(name, true)
	}

	DeleteTemplateInfoFromCache(name)
}

func DeleteTemplateInfoFromCache(name string) {
	//remove metadata from db
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	//obtain id of template by ref
	meta := bolt.TemplateByKey("nameAndOwnerAndVersion", name)
	if meta != nil && len(meta) > 0 {
		//take first element only since ref is unique
		templateId := meta[0]
		log.Check(log.WarnLevel, "Deleting template metadata entry", bolt.TemplateDel(templateId))
	}
	log.Check(log.WarnLevel, "Deleting uuid entry", bolt.DelUuidEntry(name))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
}

// GetParent return a parent of the Subutai container.
func GetParent(name string) string {
	return GetConfigItem(config.Agent.LxcPrefix+name+"/config", "subutai.parent")
}
func GetProperty(templateOrContainerName string, propertyName string) string {
	return GetConfigItem(config.Agent.LxcPrefix+templateOrContainerName+"/config", propertyName)
}

// Clone create the duplicate container from the Subutai template.
func Clone(parent, child string) error {

	parentParts := strings.Split(parent, ":")

	//create parent dataset
	fs.CreateDataset(child)

	//create partitions
	fs.CloneSnapshot(parent+"/rootfs@now", child+"/rootfs")
	fs.CloneSnapshot(parent+"/home@now", child+"/home")
	fs.CloneSnapshot(parent+"/var@now", child+"/var")
	fs.CloneSnapshot(parent+"/opt@now", child+"/opt")

	for _, file := range []string{"config", "fstab", "packages"} {
		fs.Copy(path.Join(config.Agent.LxcPrefix, parent, file), path.Join(config.Agent.LxcPrefix, child, file))
	}

	mac := Mac()
	SetContainerConf(child, [][]string{
		//{"lxc.network.script.up", "/usr/sbin/subutai-create-interface"}, //must be in template
		{"lxc.network.hwaddr", mac},
		{"lxc.network.veth.pair", strings.Replace(mac, ":", "", -1)},
		{"subutai.parent", parentParts[0]},
		{"subutai.parent.owner", parentParts[1]},
		{"subutai.parent.version", parentParts[2]},
		{"lxc.rootfs", config.Agent.LxcPrefix + child + "/rootfs"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + child + "/home home none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + child + "/opt opt none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + child + "/var var none bind,rw 0 0"},
		{"lxc.rootfs.backend", "zfs"}, //must be in template
		{"lxc.utsname", child},
	})

	//create default hostname
	ioutil.WriteFile(config.Agent.LxcPrefix+child+"/rootfs/etc/hostname", []byte(child), 0644)

	return nil
}

// QuotaRAM sets the memory quota to the Subutai container.
// If quota size argument is missing, it's just return current value.
func QuotaRAM(name string, size ...string) int {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	i, err := strconv.Atoi(size[0])
	log.Check(log.DebugLevel, "Parsing quota size", err)
	if i > 0 {
		log.Check(log.DebugLevel, "Setting memory limit", c.SetMemoryLimit(lxc.ByteSize(i*1024*1024)))
		SetContainerConf(name, [][]string{{"lxc.cgroup.memory.limit_in_bytes", size[0] + "M"}})
	}
	limit, err := c.MemoryLimit()
	log.Check(log.DebugLevel, "Getting memory limit of container: "+name, err)
	return int(limit / 1024 / 1024)
}

// QuotaCPU sets container CPU limitation and return current value in percents.
// If passed value < 100, we assume that this value mean percents.
// If passed value > 100, we assume that this value mean MHz.
func QuotaCPU(name string, size ...string) int {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	cfsPeriod := 100000
	tmp, err := strconv.Atoi(size[0])
	log.Check(log.DebugLevel, "Parsing quota size", err)
	quota := float32(tmp)

	if quota > 100 {
		out, err := ioutil.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
		freq, err := strconv.Atoi(strings.TrimSpace(string(out)))
		log.Check(log.DebugLevel, "Parsing quota size", err)
		freq = freq / 1000
		if log.Check(log.DebugLevel, "Getting CPU max frequency", err) {
			out, err := ioutil.ReadFile("/proc/cpuinfo")
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() && err == nil {
				if strings.HasPrefix(scanner.Text(), "cpu MHz") {
					freq, err = strconv.Atoi(strings.TrimSpace(strings.Split(strings.Split(scanner.Text(), ":")[1], ".")[0]))
					log.Check(log.DebugLevel, "Parsing quota size", err)
					break
				}
			}
		}
		quota = quota * 100 / float32(freq) / float32(runtime.NumCPU())
	}

	if size[0] != "" && State(name) == "RUNNING" {
		value := strconv.Itoa(int(float32(cfsPeriod) * float32(runtime.NumCPU()) * quota / 100))
		log.Check(log.DebugLevel, "Setting cpu.cfs_quota_us", c.SetCgroupItem("cpu.cfs_quota_us", value))

		SetContainerConf(name, [][]string{{"lxc.cgroup.cpu.cfs_quota_us", value}})
	}

	result, err := strconv.Atoi(c.CgroupItem("cpu.cfs_quota_us")[0])
	log.Check(log.DebugLevel, "Parsing quota size", err)
	return result * 100 / cfsPeriod / runtime.NumCPU()
}

// QuotaCPUset sets particular cores that can be used by the Subutai container.
func QuotaCPUset(name string, size ...string) string {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	if size[0] != "" {
		log.Check(log.DebugLevel, "Setting cpuset.cpus", c.SetCgroupItem("cpuset.cpus", size[0]))
		SetContainerConf(name, [][]string{{"lxc.cgroup.cpuset.cpus", size[0]}})
	}
	return c.CgroupItem("cpuset.cpus")[0]
}

// QuotaNet sets network bandwidth for the Subutai container.
func QuotaNet(name string, size ...string) string {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	nic := GetConfigItem(c.ConfigFileName(), "lxc.network.veth.pair")
	if size[0] != "" {
		SetContainerConf(name, [][]string{{"subutai.network.ratelimit", size[0]}})
	}
	return net.RateLimit(nic, size[0])
}

// SetContainerConf sets any parameter in the configuration file of the Subutai container.
//TODO use the new lxc config type
func SetContainerConf(container string, conf [][]string) error {
	confPath := config.Agent.LxcPrefix + container + "/config"
	newconf := ""

	file, err := os.Open(confPath)
	if log.Check(log.DebugLevel, "Opening container config "+confPath, err) {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(bufio.NewReader(file))
	for scanner.Scan() {
		newline := scanner.Text() + "\n"
		for i := 0; i < len(conf); i++ {
			line := strings.Split(scanner.Text(), "=")
			if len(line) > 1 && strings.Trim(line[0], " ") == conf[i][0] {
				if newline = ""; len(conf[i][1]) > 0 {
					newline = conf[i][0] + " = " + conf[i][1] + "\n"
				}
				conf = append(conf[:i], conf[i+1:]...)
				break
			}
		}
		newconf = newconf + newline
	}

	for i := range conf {
		if conf[i][1] != "" {
			newconf = newconf + conf[i][0] + " = " + conf[i][1] + "\n"
		}
	}
	return ioutil.WriteFile(confPath, []byte(newconf), 0644)
}

// GetConfigItem return any parameter from the configuration file of the Subutai container.
func GetConfigItem(path, item string) string {
	if cfg, err := os.Open(path); err == nil {
		defer cfg.Close()
		scanner := bufio.NewScanner(cfg)
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), "=")
			if strings.Trim(line[0], " ") == item {
				return strings.Trim(line[1], " ")
			}
		}
	}
	return ""
}

// SetContainerUID sets UID map shifting for the Subutai container.
// It's required option for any unprivileged LXC container.
func SetContainerUID(c string) (string, error) {
	uid := "65536"
	if bolt, err := db.New(); err == nil {
		uid = bolt.GetUuidEntry(c)
		log.Check(log.WarnLevel, "Closing database", bolt.Close())
	}

	SetContainerConf(c, [][]string{
		{"lxc.id_map", "u 0 " + uid + " 65536"},
		{"lxc.id_map", "g 0 " + uid + " 65536"},
	})

	s, err := os.Stat(config.Agent.LxcPrefix + c + "/rootfs")
	if log.Check(log.DebugLevel, "Reading container rootfs stat", err) {
		return uid, err
	}

	parentuid := strconv.Itoa(int(s.Sys().(*syscall.Stat_t).Uid))
	log.Check(log.DebugLevel, "uidmapshift rootfs",
		exec.Command("uidmapshift", "-b", config.Agent.LxcPrefix+c+"/rootfs/", parentuid, uid, "65536").Run())
	log.Check(log.DebugLevel, "uidmapshift home",
		exec.Command("uidmapshift", "-b", config.Agent.LxcPrefix+c+"/home/", parentuid, uid, "65536").Run())
	log.Check(log.DebugLevel, "uidmapshift opt",
		exec.Command("uidmapshift", "-b", config.Agent.LxcPrefix+c+"/opt/", parentuid, uid, "65536").Run())
	log.Check(log.DebugLevel, "uidmapshift var",
		exec.Command("uidmapshift", "-b", config.Agent.LxcPrefix+c+"/var/", parentuid, uid, "65536").Run())

	return uid, os.Chmod(config.Agent.LxcPrefix+c, 0755)
}

// SetDNS configures the Subutai containers to use internal DNS-server from the Resource Host.
func SetDNS(name string) {
	dns := GetConfigItem(config.Agent.LxcPrefix+name+"/config", "lxc.network.ipv4.gateway")
	if len(dns) == 0 {
		dns = "10.10.10.254"
	}

	resolv := []byte("domain\tintra.lan\nsearch\tintra.lan\nnameserver\t" + dns + "\n")
	log.Check(log.DebugLevel, "Writing resolv.conf.orig",
		ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/resolvconf/resolv.conf.d/original", resolv, 0644))
	log.Check(log.DebugLevel, "Writing resolv.conf.tail",
		ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/resolvconf/resolv.conf.d/tail", resolv, 0644))
	log.Check(log.DebugLevel, "Writing resolv.conf",
		ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/resolv.conf", resolv, 0644))
}

func CopyParentReference(name string, owner string, version string) {
	SetContainerConf(name, [][]string{
		{"subutai.template.owner", owner},
		{"subutai.template.version", version},
	})
}

// SetStaticNet sets static IP-address for the Subutai container.
func SetStaticNet(name string) {
	data, err := ioutil.ReadFile(config.Agent.LxcPrefix + name + "/rootfs/etc/network/interfaces")
	log.Check(log.WarnLevel, "Opening /etc/network/interfaces", err)

	err = ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/network/interfaces",
		[]byte(strings.Replace(string(data), "dhcp", "manual", 1)), 0644)
	log.Check(log.WarnLevel, "Setting internal eth0 interface to manual", err)
}

// DisableSSHPwd disabling SSH password access to the Subutai container.
func DisableSSHPwd(name string) {
	input, err := ioutil.ReadFile(config.Agent.LxcPrefix + name + "/rootfs/etc/ssh/sshd_config")
	if log.Check(log.DebugLevel, "Opening sshd config", err) {
		return
	}

	lines := strings.Split(string(input), "\n")

	for i, line := range lines {
		if strings.EqualFold(line, "#PasswordAuthentication yes") {
			lines[i] = "PasswordAuthentication no"
		}
	}
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(config.Agent.LxcPrefix+name+"/rootfs/etc/ssh/sshd_config", []byte(output), 0644)
	log.Check(log.WarnLevel, "Writing new sshd config", err)
}

// Mac function generates random mac address for LXC containers
func Mac() string {

	usedMacs := make(map[string]bool)
	for _, cont := range Containers() {
		cfg, err := GetConfig(path.Join(config.Agent.LxcPrefix, cont, "config"))
		//skip error
		if err == nil {
			usedMacs[cfg.GetParam("lxc.network.hwaddr")] = true
		}
	}

	buf := make([]byte, 6)

	_, err := rand.Read(buf)
	log.Check(log.ErrorLevel, "Generating random mac", err)

	mac := fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5])
	for usedMacs[mac] {

		_, err := rand.Read(buf)
		log.Check(log.ErrorLevel, "Generating random mac", err)

		mac = fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5])
	}

	return mac
}
