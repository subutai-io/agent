package container

import (
	"os"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
	"path"
)

// temporary function to provide backward compatibility with old approach
// Need to remove it in next release
func compat() {
	for _, name := range container.Containers() {
		if _, err := os.Stat(path.Join(config.Agent.LxcPrefix, name, ".start")); !os.IsNotExist(err) {
			os.Remove(path.Join(config.Agent.LxcPrefix, name, ".start"))
			container.AddMetadata(name, map[string]string{"state": "RUNNING"})
		}
	}
}

// StateRestore checks container state and starting or stopping containers if required.
func StateRestore(canRestore *bool) {
	compat()

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
				container.AddMetadata(v, map[string]string{"state": "STOPPED"})
			}
		}
	}
}

func getRunningContainers() []string {
	bolt, err := db.New()

	if !log.Check(log.WarnLevel, "Opening database", err) {
		defer bolt.Close()
		return bolt.ContainerByKey("state", "RUNNING")
	}

	return []string{}
}
