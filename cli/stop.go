package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// LxcStop stops a Subutai container with an additional state check.
func LxcStop(name string) {
	if container.IsContainer(name) && container.State(name) == "RUNNING" {
		stopped := container.Stop(name)
		for i := 0; i < 60 && !stopped; i++ {
			log.Info("Waiting for container stop (60 sec)")
			stopped = container.Stop(name)
		}
		if !stopped {
			log.Error(name + " stop failed")
		}
		log.Info(name + " stopped")
	}
}
