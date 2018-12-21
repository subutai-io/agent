package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

func LxcRestart(names ...string) {
	needHeartBeat := false
	defer func() {
		if needHeartBeat {
			sendHeartbeat()
		}
	}()

	for _, name := range names {
		if container.LxcInstanceExists(name) {
			err := container.Restart(name)

			if err != nil {
				if len(names) > 0 {
					log.Warn(name + " restart failed")
				} else {
					log.Error(name + " restart failed")
				}
			} else {
				needHeartBeat = true
				log.Info(name + " restarted")
			}
		}
	}
}
