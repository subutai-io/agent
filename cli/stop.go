package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// LxcStop stops a Subutai container with an additional state check.
func LxcStop(names ...string) {
	needHeartBeat := false
	defer func() {
		if needHeartBeat {
			sendHeartbeat()
		}
	}()

	for _, name := range names {
		if container.LxcInstanceExists(name) && container.State(name) == container.Running {
			defer sendHeartbeat()
			stopErr := container.Stop(name)
			for i := 0; i < 60 && stopErr != nil; i++ {
				log.Info("Waiting for container stop (60 sec)")
				stopErr = container.Stop(name)
			}
			if stopErr != nil {
				if len(names) > 0 {
					log.Warn(name + " stop failed")
				} else {
					log.Error(name + " stop failed")
				}
			} else {
				needHeartBeat = true
				log.Info(name + " stopped")
			}
		}
	}
}
