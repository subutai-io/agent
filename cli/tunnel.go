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
	"path"
)

//TODO to support existing tunnels, we need to remove all old tunnels and create new tunnels

// The tunnel feature is based on SSH tunnels and works in combination with Subutai Helpers and serves as an easy solution for bypassing NATs.
// In Subutai, tunnels are used to access the SS management server's web UI from the Hub, and open direct connection to containers, etc.
// There are two types of channels - local (default), which is created from destination address to host and global (-g flag), from destination to Subutai Helper node.
// Tunnels may also be set to be permanent (default) or temporary (ttl in seconds). The default destination port is 22.
// Subutai tunnels have a continuous state checking mechanism which keeps opened tunnels alive and closes outdated tunnels to keep the system network connections clean.
// This mechanism may re-create a tunnel if it was dropped unintentionally (system reboot, network interruption, etc.), but newly created tunnels will have different "entrance" address.

// TunAdd adds tunnel to specified network socket
func AddSshTunnel(socket, timeout string, ssh bool) {
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
			item.Ttl = int(time.Now().Unix()) + tout
		} else {
			item.Ttl = -1
		}
		log.Check(log.ErrorLevel, "Updating tunnel entry", db.UpdateTunnel(item))
		if ssh {
			tunnel := strings.Split(item.RemoteSocket, ":")
			fmt.Println("ssh root@" + tunnel[0] + " -p " + tunnel[1])
		} else {
			fmt.Println(item.RemoteSocket)
		}

		return
	}

	log.Check(log.WarnLevel, "Setting key permissions", os.Chmod(path.Join(config.Agent.DataPrefix, "ssh.pem"), 0600))

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
			if ssh {
				fmt.Println("ssh root@" + tunsrv + " -p " + port[2])
			} else {
				fmt.Println(tunsrv + ":" + port[2])
			}
			tunnel := &db.SshTunnel{
				Pid:          cmd.Process.Pid,
				Ttl:          -1,
				LocalSocket:  socket,
				RemoteSocket: tunsrv + ":" + port[2],
			}
			if len(timeout) > 0 {
				tout, err := strconv.Atoi(timeout)
				log.Check(log.ErrorLevel, "Converting timeout to int", err)
				tunnel.Ttl = int(time.Now().Unix()) + tout
			}
			log.Check(log.WarnLevel, "Adding new tunnel entry", db.SaveTunnel(tunnel))
			return
		}
		time.Sleep(1 * time.Second)
		line, _, err = r.ReadLine()
	}
	log.Error("Cannot get tunnel port")
}

func GetSshTunnels() (list []string) {
	tunnels, err := db.GetAllTunnels()
	if !log.Check(log.WarnLevel, "Reading tunnel list from db", err) {
		for i := 0; i < len(tunnels); i++ {
			list = append(list, fmt.Sprint("%s\t%s\t%s\n",
				tunnels[i].RemoteSocket, tunnels[i].LocalSocket, tunnels[i].Ttl))
		}
	}
	return []string{}
}

// TunDel removes tunnel entry from list and kills running tunnel process
func DelSshTunnel(socket string, pid ...int) {
	list, err := db.GetAllTunnels()
	if !log.Check(log.WarnLevel, "Reading tunnel list from db", err) {
		for _, item := range list {
			if item.LocalSocket == socket && (len(pid) == 0 || (len(pid) > 0 && item.Pid == pid[0])) {
				log.Check(log.WarnLevel, "Deleting tunnel entry", db.RemoveTunnelsByPid(item.Pid))
				f, err := ioutil.ReadFile("/proc/" + strconv.Itoa(item.Pid) + "/cmdline")
				if err == nil && strings.Contains(string(f), item.LocalSocket) {
					log.Check(log.FatalLevel, "Killing tunnel process", syscall.Kill(item.Pid, 15))
				}
			}
		}
	}
}

// TunCheck reads list, checks tunnel ttl, its state and then adds or removes required tunnels
func CheckSshTunnels() {
	list, err := db.GetAllTunnels()
	if !log.Check(log.WarnLevel, "Reading tunnel list from db", err) {
		for _, item := range list {
			log.Check(log.ErrorLevel, "Checking tunnel "+item.LocalSocket+" ttl", err)
			if item.Ttl <= int(time.Now().Unix()) && item.Ttl != -1 {
				DelSshTunnel(item.LocalSocket, item.Pid)
			} else if !tunOpen(item.RemoteSocket, item.LocalSocket) {
				DelSshTunnel(item.LocalSocket, item.Pid)
				newttl := ""
				if item.Ttl-int(time.Now().Unix()) > 0 {
					newttl = strconv.Itoa(item.Ttl - int(time.Now().Unix()))
				}
				AddSshTunnel(item.LocalSocket, newttl, false)
			}
		}
	}
}

// getArgs builds command line to execute in system
func getArgs(socket string) ([]string, string) {
	var tunsrv string
	var args []string
	cdn, err := net.LookupIP("ssh." + path.Join(config.Agent.SshJumpServer))
	log.Check(log.ErrorLevel, "Resolving nearest tunnel node address", err)
	tunsrv = cdn[0].String()
	args = []string{"-i", path.Join(config.Agent.DataPrefix, "ssh.pem"), "-N", "-p", "8022", "-R", "0:" + socket, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "tunnel@" + tunsrv}
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

func getTunnel(socket string) *db.SshTunnel {
	tunnel, err := db.FindTunnelByLocalSocket(socket)
	if !log.Check(log.WarnLevel, "Reading tunnel list from db", err) {
		return tunnel
	}
	return nil
}
