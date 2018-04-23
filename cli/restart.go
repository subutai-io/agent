package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

func LxcRestart(name string) {
	if container.LxcInstanceExists(name) {
		err := container.Restart(name)

		if err != nil {
			log.Error(name + " restart failed")
		}
		log.Info(name + " restarted")
	}
}
