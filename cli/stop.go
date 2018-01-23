package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// LxcStop stops a Subutai container with an additional state check.
func LxcStop(name string) {
	if container.ContainerOrTemplateExists(name) && container.State(name) == "RUNNING" {
		stopErr := container.Stop(name)
		for i := 0; i < 60 && stopErr != nil; i++ {
			log.Info("Waiting for container stop (60 sec)")
			stopErr = container.Stop(name)
		}
		if stopErr != nil {
			log.Error(name + " stop failed")
		}
		log.Info(name + " stopped")
	}
}
