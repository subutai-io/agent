package cli

import (
	"time"

	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// LxcStart starts a Subutai container and checks if container state changed to "running" or "starting".
// If state is not changing for 60 seconds, then the "start" operation is considered to have failed.
func LxcStart(names ...string) {
	needHeartBeat := false
	defer func() {
		if needHeartBeat {
			sendHeartbeat()
		}
	}()

	for _, name := range names {
		if container.LxcInstanceExists(name) && container.State(name) == container.Stopped {
			startErr := container.Start(name)
			for i := 0; i < 60 && startErr != nil; i++ {
				log.Info("Waiting for container start (60 sec)")
				startErr = container.Start(name)
				time.Sleep(time.Second)
			}
			if startErr != nil {
				if len(names) > 0 {
					log.Warn(name + " start failed")
				} else {
					log.Error(name + " start failed")
				}
			} else {
				needHeartBeat = true
				log.Info(name + " started")
			}
		}
	}
}
