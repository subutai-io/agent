package cli

import (
	"time"

	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/fs"
)

// LxcStart starts a Subutai container and checks if container state changed to "running" or "starting".
// If state is not changing for 60 seconds, then the "start" operation is considered to have failed.
func LxcStart(name string) {
	if container.IsContainer(name) && container.State(name) == "STOPPED" {

		fs.ReadOnly(name, false, false)

		startErr := container.Start(name)
		for i := 0; i < 60 && startErr != nil; i++ {
			log.Info("Waiting for container start (60 sec)")
			startErr = container.Start(name)
			time.Sleep(time.Second)
		}
		if startErr != nil {
			log.Error(name + " start failed")
		}
		log.Info(name + " started")
	}
}
