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
	running := bolt.ContainerByKey("state", "running")
	stopped := bolt.ContainerByKey("state", "stopped")
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	for _, v := range running {
		if container.State(v) != "RUNNING" {
			started := container.Start(v)
			for i := 0; i < 5 && !started; i++ {
				time.Sleep(time.Second)
				started = container.Start(v)
			}
		}
	}

	for _, v := range stopped {
		if container.State(v) != "STOPPED" {
			stopped := container.Stop(v)
			for i := 0; i < 5 && !stopped; i++ {
				time.Sleep(time.Second)
				stopped = container.Stop(v)
			}
		}
	}
}
