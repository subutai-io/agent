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
	"time"
	"hash/crc32"
	"github.com/nightlyone/lockfile"
	"github.com/subutai-io/agent/lib/common"
	"io"
	"github.com/subutai-io/agent/lib/net/p2p"
)

const (
	Running = "RUNNING"
	Stopped = "STOPPED"
	Unknown = "UNKNOWN"
)

//TODO add methods IsRunning, IsStopped

const Management = "management"
const ContainerDefaultIface = "eth0"

var crc32Table = crc32.MakeTable(0xD5828281)

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
	return Unknown
}

// AddMetadata adds container information to database
func AddMetadata(name string, meta map[string]string) error {
	if !LxcInstanceExists(name) {
		return errors.New("Container does not exist")
	}
	log.Check(log.ErrorLevel, "Writing container data to database", db.INSTANCE.SaveContainer(name, meta))
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

	if c.State().String() != Running {
		return errors.New("Unable to start container " + name)
	}

	AddMetadata(name, map[string]string{"state": Running})

	return nil
}

// Stop stops the Subutai container.
func Stop(name string) error {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}
	defer lxc.Release(c)

	log.Check(log.DebugLevel, "Stopping LXC container "+name, c.Stop())

	if c.State().String() != Stopped {
		return errors.New("Unable to stop container " + name)
	}

	AddMetadata(name, map[string]string{"state": Stopped})

	return nil
}

func Restart(name string) error {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}
	defer lxc.Release(c)

	if c.State().String() == Running {
		log.Check(log.DebugLevel, "Stopping LXC container "+name, c.Stop())
	}

	log.Check(log.DebugLevel, "Starting LXC container "+name, c.Start())

	if c.State().String() != Running {
		return errors.New("Unable to start container " + name)
	}

	AddMetadata(name, map[string]string{"state": Running})

	return nil
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

// AttachExec executes a command inside Subutai container.
func AttachExecOutput(name string, command []string, env ...[]string) (output string, errOutput string, err error) {
	if !LxcInstanceExists(name) {
		return "", "", errors.New("Container does not exist")
	}

	container, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(container)
	}

	if container.State() != lxc.RUNNING || err != nil {
		return "", "", errors.New("Container is " + container.State().String())
	}

	bufR, bufW, err := os.Pipe()
	if err != nil {
		return "", "", errors.New("Failed to create OS pipe")
	}
	defer bufR.Close()
	defer bufW.Close()

	bufRErr, bufWErr, err := os.Pipe()
	if err != nil {
		return "", "", errors.New("Failed to create OS pipe")
	}
	defer bufRErr.Close()
	defer bufWErr.Close()

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

	pid, err := container.RunCommandNoWait(command, options)
	log.Check(log.ErrorLevel, "Executing command inside container", err)

	var stdoutBuf, stderrBuf bytes.Buffer
	stdout := io.MultiWriter(os.Stdout, &stdoutBuf)
	stderr := io.MultiWriter(os.Stderr, &stderrBuf)
	go func() {
		io.Copy(stdout, bufR)
	}()
	go func() {
		io.Copy(stderr, bufRErr)
	}()

	proc, err := os.FindProcess(pid)
	log.Check(log.ErrorLevel, "Looking process by pid "+strconv.Itoa(pid), err)

	procState, err := proc.Wait()
	log.Check(log.ErrorLevel, "Waiting for process completion", err)

	if !procState.Success() {
		log.ErrorNoExit("Command failed")
		if status, ok := procState.Sys().(syscall.WaitStatus); ok {
			os.Exit(status.ExitStatus())
		} else {
			os.Exit(1)
		}
	}

	return string(stdoutBuf.Bytes()), string(stderrBuf.Bytes()), nil
}

// Destroy deletes the Subutai container.
func DestroyContainer(name string) error {

	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)

	if log.Check(log.DebugLevel, "Creating container object", err) {
		return err
	}

	defer lxc.Release(c)

	log.Check(log.DebugLevel, "Shutting down lxc", c.Shutdown(time.Second*120))

	for i := 1; Destroy(name, false) != nil && i < 3; i++ {
		time.Sleep(time.Second * time.Duration(i*5))
	}

	log.Check(log.ErrorLevel, "Removing container", err)

	log.Check(log.WarnLevel, "Deleting container metadata entry", db.INSTANCE.RemoveContainer(name))

	return nil
}

func DestroyTemplate(name string) {
	if !IsTemplate(name) {
		log.Error("Template " + name + " not found")
	}

	err := Destroy(name, false)

	log.Check(log.ErrorLevel, "Removing template", err)

	log.Info("Template " + name + " is destroyed")
}

func Destroy(name string, silent bool) error {

	var err error = nil

	var lock lockfile.Lockfile
	for lock, err = common.LockFile("lxc", "destroy"); err != nil; lock, err = common.LockFile("lxc", "destroy") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	//destroy child datasets
	for _, dataset := range fs.ChildDatasets {

		//destroy snapshot
		childSnapshot := path.Join(name, dataset) + "@now"
		if fs.DatasetExists(childSnapshot) {
			err = fs.RemoveDataset(childSnapshot, false)
			if !silent && err != nil {
				break
			}
		}

		//destroy dataset
		childDataset := path.Join(name, dataset)
		if fs.DatasetExists(childDataset) {
			err = fs.RemoveDataset(childDataset, false)
			if !silent && err != nil {
				break
			}
		}
	}

	//destroy parent dataset
	if (silent || err == nil) && fs.DatasetExists(name) {
		err = fs.RemoveDataset(name, false)
	}

	return err
}

func GetProperty(templateOrContainerName string, propertyName string) string {
	return GetConfigItem(path.Join(config.Agent.LxcPrefix, templateOrContainerName, "config"), propertyName)
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
	mtu := Mtu()
	SetContainerConf(child, [][]string{
		//{"lxc.network.script.up", "/usr/sbin/subutai-create-interface"}, //must be in template
		{"lxc.network.hwaddr", mac},
		{"lxc.network.veth.pair", strings.Replace(mac, ":", "", -1)},
		{"lxc.network.mtu", strconv.Itoa(mtu)},
		{"subutai.parent", parentParts[0]},
		{"subutai.parent.owner", parentParts[1]},
		{"subutai.parent.version", parentParts[2]},
		{"lxc.rootfs", path.Join(config.Agent.LxcPrefix, child, "rootfs")},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, child, "home") + " home none bind,rw 0 0"},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, child, "opt") + " opt none bind,rw 0 0"},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, child, "var") + " var none bind,rw 0 0"},
		{"lxc.rootfs.backend", "zfs"}, //must be in template
		{"lxc.utsname", child},
	})

	//create default hostname
	ioutil.WriteFile(path.Join(config.Agent.LxcPrefix, child, "/rootfs/etc/hostname"), []byte(child), 0644)

	return nil
}

func QuotaDisk(name, size string) int {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)

	if len(size) > 0 {
		vs, err := strconv.Atoi(size)
		fs.SetQuota(name, vs)
		log.Check(log.DebugLevel, "Setting disk limit of container "+name, err)
	}
	vr, err := fs.GetQuota(name)
	log.Check(log.DebugLevel, "Getting disk limit of container "+name, err)
	//convert bytes to GB
	vr /= 1024 * 1024 * 1024

	return vr
}

// QuotaRAM sets the memory quota to the Subutai container.
// If quota size argument is missing, just return current value.
func QuotaRAM(name string, size string) int {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)

	//set limit
	if size != "" {
		setLimit, err := strconv.Atoi(size)
		log.Check(log.DebugLevel, "Parsing quota size", err)
		log.Check(log.DebugLevel, "Setting memory limit", c.SetMemoryLimit(lxc.ByteSize(setLimit*1024*1024)))
		SetContainerConf(name, [][]string{{"lxc.cgroup.memory.limit_in_bytes", size + "M"}})
	}

	limit, err := c.MemoryLimit()
	if limit == 9223372036854771712 {
		limit = 0
	}
	log.Check(log.DebugLevel, "Getting memory limit of container: "+name, err)
	return int(limit / 1024 / 1024)
}

//todo remove MHz just leave %
// QuotaCPU sets container CPU limitation and return current value in percents.
// If passed value < 100, we assume that this value mean percents.
// If passed value > 100, we assume that this value mean MHz.
func QuotaCPU(name string, size string) int {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	cfsPeriod := 100000
	var quota float32;
	if size != "" {
		tmp, err := strconv.Atoi(size)
		log.Check(log.DebugLevel, "Parsing quota size", err)
		quota = float32(tmp)
	}

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

	if size != "" && State(name) == Running {
		value := strconv.Itoa(int(float32(cfsPeriod) * float32(runtime.NumCPU()) * quota / 100))
		log.Check(log.DebugLevel, "Setting cpu.cfs_quota_us", c.SetCgroupItem("cpu.cfs_quota_us", value))

		SetContainerConf(name, [][]string{{"lxc.cgroup.cpu.cfs_quota_us", value}})
	}

	result, err := strconv.Atoi(c.CgroupItem("cpu.cfs_quota_us")[0])
	log.Check(log.DebugLevel, "Parsing quota size", err)
	return result * 100 / cfsPeriod / runtime.NumCPU()
}

// QuotaCPUset sets particular cores that can be used by the Subutai container.
func QuotaCPUset(name string, size string) string {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	if size != "" {
		log.Check(log.DebugLevel, "Setting cpuset.cpus", c.SetCgroupItem("cpuset.cpus", size))
		SetContainerConf(name, [][]string{{"lxc.cgroup.cpuset.cpus", size}})
	}
	return c.CgroupItem("cpuset.cpus")[0]
}

// QuotaNet sets network bandwidth for the Subutai container.
func QuotaNet(name string, size string) string {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)
	nic := GetConfigItem(c.ConfigFileName(), "lxc.network.veth.pair")
	if size != "" {
		SetContainerConf(name, [][]string{{"subutai.network.ratelimit", size}})
	}
	return net.RateLimit(nic, size)
}

// SetContainerConf sets any parameter in the configuration file of the Subutai container.
func SetContainerConf(container string, conf [][]string) error {
	confPath := path.Join(config.Agent.LxcPrefix, container, "config")
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

func GetContainerUID(container string) string {
	sum := crc32.Checksum([]byte(container), crc32Table)
	uid := 65536 + 65536*(sum%100)
	return strconv.FormatUint(uint64(uid), 10)
}

// SetContainerUID sets UID map shifting for the Subutai container.
// It's required option for any unprivileged LXC container.
func SetContainerUID(c string) (string, error) {
	uid := GetContainerUID(c)

	SetContainerConf(c, [][]string{
		{"lxc.id_map", "u 0 " + uid + " 65536"},
		{"lxc.id_map", "g 0 " + uid + " 65536"},
	})

	s, err := os.Stat(path.Join(config.Agent.LxcPrefix, c, "rootfs"))
	if log.Check(log.DebugLevel, "Reading container rootfs stat", err) {
		return uid, err
	}

	parentuid := strconv.Itoa(int(s.Sys().(*syscall.Stat_t).Uid))
	log.Check(log.DebugLevel, "uidmapshift rootfs",
		exec.Command("uidmapshift", "-b", path.Join(config.Agent.LxcPrefix, c, "rootfs"), parentuid, uid, "65536").Run())
	log.Check(log.DebugLevel, "uidmapshift home",
		exec.Command("uidmapshift", "-b", path.Join(config.Agent.LxcPrefix, c, "home"), parentuid, uid, "65536").Run())
	log.Check(log.DebugLevel, "uidmapshift opt",
		exec.Command("uidmapshift", "-b", path.Join(config.Agent.LxcPrefix, c, "opt"), parentuid, uid, "65536").Run())
	log.Check(log.DebugLevel, "uidmapshift var",
		exec.Command("uidmapshift", "-b", path.Join(config.Agent.LxcPrefix, c, "var"), parentuid, uid, "65536").Run())

	return uid, os.Chmod(path.Join(config.Agent.LxcPrefix, c), 0755)
}

// SetDNS configures the Subutai containers to use internal DNS-server from the Resource Host.
func SetDNS(name string) {
	dns := GetProperty(name, "lxc.network.ipv4.gateway")
	if len(dns) == 0 {
		dns = "10.10.10.254"
	}

	resolv := []byte("domain\tintra.lan\nsearch\tintra.lan\nnameserver\t" + dns + "\n")
	log.Check(log.DebugLevel, "Writing resolv.conf.orig",
		ioutil.WriteFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/resolvconf/resolv.conf.d/original"), resolv, 0644))
	log.Check(log.DebugLevel, "Writing resolv.conf.tail",
		ioutil.WriteFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/resolvconf/resolv.conf.d/tail"), resolv, 0644))
	log.Check(log.DebugLevel, "Writing resolv.conf",
		ioutil.WriteFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/resolv.conf"), resolv, 0644))
}

func CopyParentReference(name string, owner string, version string) {
	SetContainerConf(name, [][]string{
		{"subutai.template.owner", owner},
		{"subutai.template.version", version},
	})
}

// SetStaticNet sets static IP-address for the Subutai container.
func SetStaticNet(name string) {
	data, err := ioutil.ReadFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/network/interfaces"))
	log.Check(log.WarnLevel, "Opening /etc/network/interfaces", err)

	err = ioutil.WriteFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/network/interfaces"),
		[]byte(strings.Replace(string(data), "dhcp", "manual", 1)), 0644)
	log.Check(log.WarnLevel, "Setting internal eth0 interface to manual", err)
}

// DisableSSHPwd disabling SSH password access to the Subutai container.
func DisableSSHPwd(name string) {
	input, err := ioutil.ReadFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/ssh/sshd_config"))
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
	err = ioutil.WriteFile(path.Join(config.Agent.LxcPrefix, name, "/rootfs/etc/ssh/sshd_config"), []byte(output), 0644)
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

func Mtu() int {
	return p2p.Mtu()
}

func GetIp(name string) string {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err == nil {
		defer lxc.Release(c)
	}
	log.Check(log.DebugLevel, "Looking for container: "+name, err)

	listip, err := c.IPAddress(ContainerDefaultIface)
	log.Check(log.DebugLevel, "Getting ip of container "+name, err)

	return strings.Join(listip, " ")
}
