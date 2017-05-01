// Package cli is a set of commands which are meant to provide a control interface
// for different system components such as LXC, BTRFS, OVS, etc.
// The CLI is an abstraction layer between the system and the SS Management application, but may also be used manually.
package cli

import (
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"gopkg.in/lxc/go-lxc.v2"
)

// LxcAttach allows user to use container's TTY.
//
// `name` should be available running Subutai container,
// otherwise command will return error message and non-zero exit code.
func LxcAttach(name string, cmd []string) {
	c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
	log.Check(log.ErrorLevel, "Creating container object", err)

	options := lxc.DefaultAttachOptions
	options.EnvToKeep = []string{"TERM", "USER", "LS_COLORS"}
	options.ClearEnv = true

	if len(cmd) > 0 {
		_, err = c.RunCommand(cmd, options)
		log.Check(log.ErrorLevel, "Attaching shell", err)
	} else {
		log.Check(log.ErrorLevel, "Attaching shell", c.AttachShell(options))
	}
}
