package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// LxcStop stops a Subutai container with an additional state check.
func LxcStop(name string) {
	if container.IsContainer(name) && container.State(name) == "RUNNING" {
		container.Stop(name)
	}
	if container.State(name) == "STOPPED" {
		log.Info(name + " stopped")
	} else {
		log.Error(name + " stop failed")
	}
}
