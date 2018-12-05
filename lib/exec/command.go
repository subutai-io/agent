package exec

import (
	"os/exec"
	"fmt"
	"bytes"
	"strings"
	"github.com/subutai-io/agent/log"
	"os"
	"io"
	"github.com/subutai-io/agent/config"
)

// executes command
// returns stdout and nil if command executes successfully
// returns stderr and error if command executes with error
func ExecB(command string, args ...string) ([]byte, error) {

	log.Debug("Executing command " + command + " " + strings.Join(args, " "))

	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "IPFS_PATH="+config.CDN.IpfsPath)

	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		return []byte(fmt.Sprint(err) + ": " + stderr.String()), err
	}

	return out.Bytes(), nil
}

// executes command
// returns stdout and nil if command executes successfully
// returns stderr and error if command executes with error
func Execute(command string, args ...string) (string, error) {

	log.Debug("Executing command " + command + " " + strings.Join(args, " "))

	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "IPFS_PATH="+config.CDN.IpfsPath)

	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		errMsg := stderr.String()
		if strings.TrimSpace(errMsg) == "" {
			errMsg = out.String()
		}
		return fmt.Sprint(err) + ": " + errMsg, err
	}

	return out.String(), nil
}

// executes command using /bin/bash
// returns stdout and nil if command executes successfully
// returns stderr and error if command executes with error
func ExecuteWithBash(command string) (string, error) {

	return Execute("/bin/bash", "-c", command)
}

// executes command
// returns nil if command executes successfully
// returns error if command executes with error
func Exec(command string, args ...string) error {

	_, err := Execute(command, args...)

	return err
}

// executes command and prints its output progressively
// returns nil if command executes successfully
// returns error if command executes with error
func ExecuteOutput(command string, env map[string]string, args ... string) (string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ()
	for key, val := range env {
		cmd.Env = append(cmd.Env, key+"="+val)
	}

	stdoutIn, _ := cmd.StdoutPipe()
	stderrIn, _ := cmd.StderrPipe()

	stdout := io.MultiWriter(os.Stdout, &stdoutBuf)
	stderr := io.MultiWriter(os.Stderr, &stderrBuf)
	err := cmd.Start()
	if err != nil {
		return fmt.Sprint(err), err
	}

	go func() {
		io.Copy(stdout, stdoutIn)
	}()

	go func() {
		io.Copy(stderr, stderrIn)
	}()

	err = cmd.Wait()
	if err != nil {
		return fmt.Sprint(err), err
	}

	outStr := string(stdoutBuf.Bytes())
	return outStr, nil
}
