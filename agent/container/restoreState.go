package container

import (
	"time"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// StateRestore checks container state and starting or stopping containers if required.
func StateRestore(canRestore *bool) {
	active := getRunningContainers()

	for _, v := range active {
		if !*canRestore {
			return
		}
		if container.State(v) != "RUNNING" {
			log.Debug("Starting container " + v)
			startErr := container.Start(v)
			for i := 0; i < 5 && startErr != nil; i++ {
				if !*canRestore {
					return
				}
				log.Debug("Retrying container " + v + " start")
				time.Sleep(time.Second * time.Duration(5+i))
				startErr = container.Start(v)
			}
			if startErr != nil {
				log.Warn("Failed to start container " + v + ": " + startErr.Error())
				container.AddMetadata(v, map[string]string{"state": "STOPPED"})
			}
		}
	}
}

func getRunningContainers() []string {
	list, err := db.INSTANCE.ContainerByKey("state", "RUNNING")

	if !log.Check(log.WarnLevel, "Getting list of running containers", err) {
		return list
	}

	return []string{}
}
