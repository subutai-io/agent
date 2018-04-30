package cli

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/log"
	"os"
)

// The tunnel feature is based on SSH tunnels and works in combination with Subutai Helpers and serves as an easy solution for bypassing NATs.
// In Subutai, tunnels are used to access the SS management server's web UI from the Hub, and open direct connection to containers, etc.
// There are two types of channels - local (default), which is created from destination address to host and global (-g flag), from destination to Subutai Helper node.
// Tunnels may also be set to be permanent (default) or temporary (ttl in seconds). The default destination port is 22.
// Subutai tunnels have a continuous state checking mechanism which keeps opened tunnels alive and closes outdated tunnels to keep the system network connections clean.
// This mechanism may re-create a tunnel if it was dropped unintentionally (system reboot, network interruption, etc.), but newly created tunnels will have different "entrance" address.

// TunAdd adds tunnel to specified network socket
func TunAdd(socket, timeout string) {
	if len(socket) == 0 {
		log.Error("Please specify socket")
	}

	if len(strings.Split(socket, ":")) == 1 {
		socket = socket + ":22"
	}

	if item := getTunnel(socket); item != nil {
		if len(timeout) > 0 {
			tout, err := strconv.Atoi(timeout)
			log.Check(log.ErrorLevel, "Converting timeout to int", err)
			item["ttl"] = strconv.Itoa(int(time.Now().Unix()) + tout)
		} else {
			item["ttl"] = "-1"
		}
		localDB, err := db.New()
		if !log.Check(log.WarnLevel, "Opening database", err) {
			log.Check(log.WarnLevel, "Updating tunnel entry", localDB.AddTunEntry(item))
			log.Check(log.WarnLevel, "Closing database", localDB.Close())
		}
		fmt.Println(item["remote"])
		return
	}

	log.Check(log.WarnLevel, "Setting key permissions", os.Chmod(config.Agent.DataPrefix+"ssh.pem", 0600))

	args, tunsrv := getArgs(socket)

	log.Debug("Executing command ssh " + strings.Join(args, " "))

	cmd := exec.Command("ssh", args...)

	stderr, _ := cmd.StderrPipe()
	log.Check(log.FatalLevel, "Creating SSH tunnel to "+socket, cmd.Start())
	r := bufio.NewReader(stderr)
	line, _, err := r.ReadLine()
	log.Check(log.FatalLevel, "Reading tunnel output pipe", err)
	for i := 0; err == nil && i < 10; i++ {
		log.Debug("Ssh tunnel output: \n" + string(line))
		if strings.Contains(string(line), "Allocated port") {
			port := strings.Fields(string(line))
			fmt.Println(tunsrv + ":" + port[2])
			tunnel := map[string]string{
				"pid":    strconv.Itoa(cmd.Process.Pid),
				"local":  socket,
				"remote": tunsrv + ":" + port[2],
				"ttl":    "-1",
			}
			if len(timeout) > 0 {
				tout, err := strconv.Atoi(timeout)
				log.Check(log.ErrorLevel, "Converting timeout to int", err)
				tunnel["ttl"] = strconv.Itoa(int(time.Now().Unix()) + tout)
			}
			bolt, err := db.New()
			log.Check(log.WarnLevel, "Opening database", err)
			log.Check(log.WarnLevel, "Adding new tunnel entry", bolt.AddTunEntry(tunnel))
			log.Check(log.WarnLevel, "Closing database", bolt.Close())
			return
		}
		time.Sleep(1 * time.Second)
		line, _, err = r.ReadLine()
	}
	log.Error("Cannot get tunnel port")
}

// TunList performs tunnel check and shows "alive" tunnels
func TunList() {
	TunCheck()
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	list := bolt.GetTunList()
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for _, item := range list {
		fmt.Printf("%s\t%s\t%s\n", item["remote"], item["local"], item["ttl"])
	}
}

// TunDel removes tunnel entry from list and kills running tunnel process
func TunDel(socket string, pid ...string) {
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	list := bolt.GetTunList()
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for _, item := range list {
		if item["local"] == socket && (len(pid) == 0 || (len(pid[0]) != 0 && item["pid"] == pid[0])) {
			bolt, err := db.New()
			log.Check(log.WarnLevel, "Opening database", err)
			log.Check(log.WarnLevel, "Deleting tunnel entry", bolt.DelTunEntry(item["pid"]))
			log.Check(log.WarnLevel, "Closing database", bolt.Close())
			f, err := ioutil.ReadFile("/proc/" + item["pid"] + "/cmdline")
			if err == nil && strings.Contains(string(f), item["local"]) {
				pid, err := strconv.Atoi(item["pid"])
				log.Check(log.FatalLevel, "Converting pid to int", err)
				log.Check(log.FatalLevel, "Killing tunnel process", syscall.Kill(pid, 15))
			}
		}
	}
}

// TunCheck reads list, checks tunnel ttl, its state and then adds or removes required tunnels
func TunCheck() {
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	list := bolt.GetTunList()
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for _, item := range list {
		ttl, err := strconv.Atoi(item["ttl"])
		log.Check(log.ErrorLevel, "Checking tunnel "+item["local"]+" ttl", err)
		if ttl <= int(time.Now().Unix()) && ttl != -1 {
			TunDel(item["local"], item["pid"])
		} else if !tunOpen(item["remote"], item["local"]) {
			TunDel(item["local"], item["pid"])
			newttl := ""
			if ttl-int(time.Now().Unix()) > 0 {
				newttl = strconv.Itoa(ttl - int(time.Now().Unix()))
			}
			TunAdd(item["local"], newttl)
		}
	}
}

// getArgs builds command line to execute in system
func getArgs(socket string) ([]string, string) {
	var tunsrv string
	var args []string
	cdn, err := net.LookupIP("ssh." + config.CDN.URL)
	log.Check(log.ErrorLevel, "Resolving nearest tunnel node address", err)
	tunsrv = cdn[0].String()
	args = []string{"-i", config.Agent.DataPrefix + "ssh.pem", "-N", "-p", "8022", "-R", "0:" + socket, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "tunnel@" + tunsrv}
	return args, tunsrv
}

// tunOpen checks tunnel sockets state to define if tunnel is alive
func tunOpen(remote, local string) bool {
	if _, err := net.DialTimeout("tcp", local, time.Second*1); err != nil {
		log.Debug("Local socket connectivity problem")
		return true
	} else if _, err := net.DialTimeout("tcp", remote, time.Second*2); err != nil {
		log.Debug("Remote socket connectivity problem")
		return false
	}
	return true
}

func getTunnel(socket string) map[string]string {
	localDB, err := db.New()
	if !log.Check(log.WarnLevel, "Opening database", err) {
		list := localDB.GetTunList()
		log.Check(log.WarnLevel, "Closing database", localDB.Close())

		for _, item := range list {
			if item["local"] == socket {
				return item
			}
		}
	}
	return nil
}
