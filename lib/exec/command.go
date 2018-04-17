package exec

import (
	"os/exec"
	"fmt"
	"bytes"
	"strings"
	"github.com/subutai-io/agent/log"
)

// executes command
// returns stdout and nil if command executes successfully
// returns stderr and error if command executes with error
func Execute(command string, args ...string) (string, error) {

	log.Debug("Executing command " + command + " " + strings.Join(args, " "))

	cmd := exec.Command(command, args...)

	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		return fmt.Sprint(err) + ": " + stderr.String(), err
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
