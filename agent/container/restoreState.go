package container

import (
	"time"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

func StateRestore() {
	for {
		doRestore()
		time.Sleep(time.Second * 30)
	}
}

func doRestore() {
	active := getRunningContainers()

	for _, v := range active {
		if container.State(v) != container.Running {
			log.Debug("Starting container " + v)
			startErr := container.Start(v)
			for i := 0; i < 5 && startErr != nil; i++ {
				log.Debug("Retrying container " + v + " start")
				time.Sleep(time.Second * time.Duration(5+i))
				startErr = container.Start(v)
			}
			if startErr != nil {
				log.Warn("Failed to start container " + v + ": " + startErr.Error())
				container.AddMetadata(v, map[string]string{"state": container.Stopped})
			}
		}
	}
}

func getRunningContainers() []string {
	list, err := db.INSTANCE.ContainerByKey("state", container.Running)

	if !log.Check(log.WarnLevel, "Getting list of running containers", err) {
		return list
	}

	return []string{}
}
