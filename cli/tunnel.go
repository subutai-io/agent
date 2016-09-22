package lib

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
)

func TunAdd(socket, timeout string, g bool) {
	// "args" here to provide back compatibility with old "-g" flag. Need to remove in future.

	if len(socket) == 0 {
		log.Error("Please specify socket")
	}

	if len(strings.Split(socket, ":")) == 1 {
		socket = socket + ":22"
	}

	args, tunsrv := getArgs(socket)
	cmd := exec.Command("ssh", args...)
	if len(timeout) > 0 {
		args = append([]string{timeout, "ssh"}, args...)
		cmd = exec.Command("timeout", args...)
	}

	stderr, _ := cmd.StderrPipe()
	log.Check(log.FatalLevel, "Creating SSH tunnel to "+socket, cmd.Start())
	r := bufio.NewReader(stderr)
	line, _, err := r.ReadLine()
	log.Check(log.FatalLevel, "Reading tunnel output pipe", err)
	for i := 0; err == nil && i < 10; i++ {
		if strings.Contains(string(line), "Allocated port") {
			port := strings.Fields(string(line))
			fmt.Println(tunsrv + ":" + port[2])
			if len(timeout) > 0 {
				tout, err := strconv.Atoi(timeout)
				log.Check(log.ErrorLevel, "Converting timeout to int", err)
				addToList("ssh-tunnels", tunsrv+":"+port[2]+" "+socket+" "+strconv.Itoa(int(time.Now().Unix())+tout)+" "+strconv.Itoa(cmd.Process.Pid))
			} else {
				addToList("ssh-tunnels", tunsrv+":"+port[2]+" "+socket+" -1 "+strconv.Itoa(cmd.Process.Pid))
			}
			return
		}
		time.Sleep(1 * time.Second)
		line, _, err = r.ReadLine()
	}
	log.Error("Cannot get tunnel port")
}

func TunList() {
	TunCheck()
	f := getList()
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		row := strings.Split(scanner.Text(), " ")
		if len(row) == 4 {
			fmt.Println(row[0] + " " + row[1] + " " + row[2])
		}
	}
	log.Check(log.WarnLevel, "Scanning tunnel list", scanner.Err())
}

func TunDel(socket string, pid ...string) {
	f := getList()
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		row := strings.Split(scanner.Text(), " ")
		if len(row) == 4 && row[1] == socket && (len(pid) == 0 || (len(pid[0]) != 0 && row[3] == pid[0])) {
			delEntry(row[3])
			f, err := ioutil.ReadFile("/proc/" + row[3] + "/cmdline")
			if err == nil && strings.Contains(string(f), row[1]) {
				pid, err := strconv.Atoi(row[3])
				log.Check(log.FatalLevel, "Converting pid to int", err)
				pgid, err := syscall.Getpgid(pid)
				log.Check(log.FatalLevel, "Getting process group id", err)
				log.Check(log.FatalLevel, "Killing tunnel process", syscall.Kill(-pgid, 15))
			}
		}
	}
	log.Check(log.WarnLevel, "Scanning tunnel list", scanner.Err())
}

func TunCheck() {
	f := getList()
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		row := strings.Split(scanner.Text(), " ")
		if len(row) == 4 {
			ttl, err := strconv.Atoi(row[2])
			log.Check(log.ErrorLevel, "Checking tunnel "+row[1]+" ttl", err)
			if ttl <= int(time.Now().Unix()) && ttl != -1 {
				TunDel(row[1], row[3])
			} else if !tunOpen(row[0], row[1]) {
				TunDel(row[1], row[3])
				newttl := ""
				if ttl-int(time.Now().Unix()) > 0 {
					newttl = strconv.Itoa(ttl - int(time.Now().Unix()))
				}
				TunAdd(row[1], newttl, false)
			}
		}
	}
	log.Check(log.WarnLevel, "Scanning tunnel list", scanner.Err())
}

func getList() *os.File {
	f, err := os.Open(config.Agent.DataPrefix + "subutai-network/ssh-tunnels")
	if os.IsNotExist(err) {
		f, err = os.Create(config.Agent.DataPrefix + "subutai-network/ssh-tunnels")
		log.Check(log.FatalLevel, "Creating tunnel list", err)
	} else if err != nil {
		log.Error("Opening tunnel list " + err.Error())
	}
	return f
}

func getArgs(socket string) ([]string, string) {
	var tunsrv string
	var args []string
	cdn, err := net.LookupIP(config.Cdn.Url)
	log.Check(log.ErrorLevel, "Resolving nearest tunnel node address", err)
	tunsrv = cdn[0].String()
	args = []string{"-i", config.Agent.AppPrefix + "etc/ssh.pem", "-N", "-p", "8022", "-R", "0:" + socket, "-o", "StrictHostKeyChecking=no", "tunnel@" + tunsrv}
	return args, tunsrv
}

func addToList(file, line string) {
	f, err := os.OpenFile(config.Agent.DataPrefix+"subutai-network/"+file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	log.Check(log.ErrorLevel, "Writing tunnel list", err)
	defer f.Close()

	if _, err = f.WriteString(line + "\n"); err != nil {
		log.Error("Appending new line to list")
	}
}

func delEntry(pid string) {
	f := getList()
	defer f.Close()

	tmp, err := os.Create(config.Agent.DataPrefix + "subutai-network/ssh-tunnels.new")
	log.Check(log.ErrorLevel, "Creating new list", err)
	tmp.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		row := strings.Split(scanner.Text(), " ")
		if len(row) == 4 && row[3] != pid {
			addToList("ssh-tunnels.new", scanner.Text())
		}
	}
	log.Check(log.ErrorLevel, "Replacing old list",
		os.Rename(config.Agent.DataPrefix+"subutai-network/ssh-tunnels.new", config.Agent.DataPrefix+"subutai-network/ssh-tunnels"))
}

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
