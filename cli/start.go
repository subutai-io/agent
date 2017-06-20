package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// LxcStart starts a Subutai container and checks if container state changed to "running" or "starting".
// If state is not changing for 60 seconds, then the "start" operation is considered to have failed.
func LxcStart(name string) {
	if container.IsContainer(name) && container.State(name) == "STOPPED" {
		started := container.Start(name)
		for i := 0; i < 60 && !started; i++ {
			log.Info("Waiting for container start (60 sec)")
			started = container.Start(name)
		}
		if !started {
			log.Error(name + " start failed")
		}
		log.Info(name + " started")
	}
}
