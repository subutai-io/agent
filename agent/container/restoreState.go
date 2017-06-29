package container

import (
	"time"

	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// StateRestore checks container state and starting or stopping containers if required.
func StateRestore() {
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	active := bolt.ContainerByKey("state", "RUNNING")
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for _, v := range active {
		if container.State(v) != "RUNNING" {
			log.Debug("Starting container " + v)
			startErr := container.Start(v)
			for i := 0; i < 5 && startErr != nil; i++ {
				log.Debug("Retrying container " + v + " start")
				time.Sleep(time.Second)
				startErr = container.Start(v)
			}
		}
	}
}
