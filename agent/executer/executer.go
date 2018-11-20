// Package executer is responsible for both - command execution inside host and container
package executer

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gopkg.in/lxc/go-lxc.v2"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/common"
	"github.com/subutai-io/agent/lib/gpg"
	"path"
	"encoding/json"
)

func Execute(rsp EncRequest, responseCallback func(msg []byte, deadline time.Time), contName string) {
	var req Request
	var md, pub, keyring string

	if rsp.HostID == gpg.GetRhFingerprint() {
		md = gpg.DecryptWrapper(rsp.Request)
	} else {

		if contName == "" {
			return
		}

		pub = path.Join(config.Agent.LxcPrefix, contName, "public.pub")
		keyring = path.Join(config.Agent.LxcPrefix, contName, "secret.sec")
		log.Info("Getting public keyring", "keyring", keyring)
		md = gpg.DecryptWrapper(rsp.Request, keyring, pub)
	}

	if log.Check(log.WarnLevel, "Decrypting request", json.Unmarshal([]byte(md), &req.Request)) {
		return
	}

	//create channels for stdout and stderr
	sOut := make(chan ResponseOptions)
	if rsp.HostID == gpg.GetRhFingerprint() {
		go execInHost(req.Request, sOut)
	} else {
		go execInContainer(contName, req.Request, sOut)
	}

	for sOut != nil {
		if elem, ok := <-sOut; ok {
			resp := Response{ResponseOpts: elem}
			jsonR, err := json.Marshal(resp)
			log.Check(log.WarnLevel, "Marshal response", err)

			var payload []byte
			if rsp.HostID == gpg.GetRhFingerprint() {
				payload, err = gpg.EncryptWrapper(config.Agent.GpgUser, config.Management.GpgUser, jsonR)
			} else {
				payload, err = gpg.EncryptWrapper(contName, config.Management.GpgUser, jsonR, pub, keyring)
			}
			if err == nil && len(payload) > 0 {
				message, err := json.Marshal(map[string]string{"hostId": elem.ID, "response": string(payload)})
				log.Check(log.WarnLevel, "Marshal response json "+elem.CommandID, err)
				go responseCallback(message, time.Now().Add(time.Second*time.Duration(req.Request.Timeout)))
			}
		} else {
			sOut = nil
		}
	}

}

// execInHost executes request inside Resource host
// and sends output as response.
func execInHost(req RequestOptions, outCh chan<- ResponseOptions) {
	defer close(outCh)

	cmd := buildCmd(&req)

	if cmd == nil {
		return
	}
	rop, wop, err := os.Pipe()
	if err != nil {
		return
	}
	defer rop.Close()

	rep, wep, err := os.Pipe()
	if err != nil {
		return
	}
	defer rep.Close()

	cmd.Stdout = wop
	cmd.Stderr = wep
	if req.IsDaemon == 1 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Setpgid = true
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	}

	err = cmd.Start()

	log.Check(log.WarnLevel, "Executing command: "+req.CommandID+" "+req.Command+" "+strings.Join(req.Args, " "), err)

	log.Check(log.DebugLevel, "Closing standard output", wop.Close())
	log.Check(log.DebugLevel, "Closing error output", wep.Close())

	stdout := make(chan string)
	stderr := make(chan string)
	go outputReader(rop, stdout)
	go outputReader(rep, stderr)

	var response = genericResponse(req)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		outputSender(stdout, stderr, outCh, &response)
	}()

	done := make(chan error)

	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		wg.Wait()
		response.ExitCode = "0"
		if req.IsDaemon != 1 && cmd.ProcessState != nil {
			response.ExitCode = strconv.Itoa(cmd.ProcessState.Sys().(syscall.WaitStatus).ExitStatus())
		}
		outCh <- response
	case <-time.After(time.Duration(req.Timeout) * time.Second):
		if req.IsDaemon == 1 {
			response.ExitCode = "0"
			outCh <- response
			<-done
		} else {
			log.Check(log.DebugLevel, "Killing process by timeout", cmd.Process.Kill())
			response.Type = "EXECUTE_TIMEOUT"
			_, err = cmd.Process.Wait()
			log.Check(log.DebugLevel, "Killing process to finish", err)
			if cmd.ProcessState != nil {
				response.ExitCode = strconv.Itoa(cmd.ProcessState.Sys().(syscall.WaitStatus).ExitStatus())
			} else {
				response.ExitCode = "-1"
			}
			outCh <- response
		}
	}
}

func outputReader(read *os.File, ch chan<- string) {
	r := bufio.NewReader(read)
	for line, isPrefix, err := r.ReadLine(); err == nil; line, isPrefix, err = r.ReadLine() {
		if isPrefix {
			ch <- string(line)
		} else {
			ch <- string(line) + "\n"
		}
	}
	close(ch)
}

func outputSender(stdout, stderr chan string, ch chan<- ResponseOptions, response *ResponseOptions) {
	ticker := time.NewTicker(time.Second * 10)
	tickerChan := ticker.C
	for stdout != nil || stderr != nil {
		alive := false
		select {
		case buf, ok := <-stdout:
			response.StdOut = response.StdOut + buf
			if !ok {
				stdout = nil
			}
		case buf, ok := <-stderr:
			response.StdErr = response.StdErr + buf
			if !ok {
				stderr = nil
			}
		case <-tickerChan:
			alive = true
		}
		if len(response.StdOut) > 50000 || len(response.StdErr) > 50000 || alive {
			ok := send(ch, response)
			response.StdErr, response.StdOut = "", ""
			response.ResponseNumber++
			if !ok {
				break
			}
		}
	}
	ticker.Stop()
}

func send(ch chan<- ResponseOptions, response *ResponseOptions) bool {
	defer common.Recover()

	ch <- *response

	return true
}

func buildCmd(r *RequestOptions) *exec.Cmd {
	usr, err := user.Lookup(r.RunAs)
	if log.Check(log.WarnLevel, "User lookup: "+r.RunAs, err) {
		return nil
	}
	uid, err := strconv.Atoi(usr.Uid)
	if log.Check(log.WarnLevel, "UID lookup: "+usr.Uid, err) {
		return nil
	}
	gid, err := strconv.Atoi(usr.Gid)
	if log.Check(log.WarnLevel, "GID lookup: "+usr.Gid, err) {
		return nil
	}
	gid32 := *(*uint32)(unsafe.Pointer(&gid))
	uid32 := *(*uint32)(unsafe.Pointer(&uid))

	var buff bytes.Buffer
	_, err = buff.WriteString(r.Command + " ")
	if err != nil {
		return nil
	}
	for _, arg := range r.Args {
		_, err = buff.WriteString("\"" + arg + "\" ")
		if err != nil {
			return nil
		}
	}
	cmd := exec.Command("/bin/bash", "-c", buff.String())
	cmd.Dir = r.WorkingDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid32, Gid: gid32}

	return cmd
}

//prepare basic response
func genericResponse(req RequestOptions) ResponseOptions {
	return ResponseOptions{
		Type:           "EXECUTE_RESPONSE",
		CommandID:      req.CommandID,
		ID:             req.ID,
		ResponseNumber: 1,
	}
}

// execInContainer executes request inside Container host
// and sends output as response.
func execInContainer(name string, req RequestOptions, outCh chan<- ResponseOptions) error {
	defer close(outCh)

	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	if err != nil {
		return err
	}
	defer lxc.Release(c)

	rop, wop, err := os.Pipe()
	if err != nil {
		return err
	}
	defer rop.Close()

	rep, wep, err := os.Pipe()
	if err != nil {
		return err
	}
	defer rep.Close()

	opts := lxc.DefaultAttachOptions
	opts.UID, opts.GID = credentials(req.RunAs, name)
	opts.StdoutFd = wop.Fd()
	opts.StderrFd = wep.Fd()
	opts.Cwd = req.WorkingDir
	opts.EnvToKeep = []string{"TERM", "USER", "LS_COLORS"}
	opts.ClearEnv = true

	var exitCode int
	var cmd bytes.Buffer

	_, err = cmd.WriteString(req.Command)
	if err != nil {
		return err
	}
	for _, a := range req.Args {
		_, err = cmd.WriteString(a + " ")
		if err != nil {
			return err
		}
	}

	log.Debug("Executing command in container " + name + ":" + cmd.String())
	go func() {
		exitCode, err = c.RunCommandStatus([]string{"timeout", strconv.Itoa(req.Timeout), "/bin/bash", "-c", cmd.String()}, opts)
		log.Check(log.DebugLevel, "Executing command inside container", err)
		log.Check(log.DebugLevel, "Closing standard output", wop.Close())
		log.Check(log.DebugLevel, "Closing error output", wep.Close())
	}()

	stdout := make(chan string)
	stderr := make(chan string)
	go outputReader(rop, stdout)
	go outputReader(rep, stderr)

	var response = genericResponse(req)
	outputSender(stdout, stderr, outCh, &response)
	if exitCode == 0 {
		response.Type = "EXECUTE_RESPONSE"
	} else if exitCode == 124 {
		response.Type = "EXECUTE_TIMEOUT"
	}
	response.ExitCode = strconv.Itoa(exitCode)

	outCh <- response

	return nil
}

// Credentials returns information about IDs from container. This informations is user for command execution only.
func credentials(name, container string) (uid int, gid int) {
	thePath := path.Join(config.Agent.LxcPrefix, container, "/rootfs/etc/passwd")
	u, g := parsePasswd(thePath, name)
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
