package cli

import (
	"os"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// Checkpoint creates container memory dump on disk using CRIU functionality
func Checkpoint(name string, restore, stop bool) {
	switch restore {
	case true:
		log.Info("Restoring container state")
		log.Check(log.ErrorLevel, "Restoring checkpoint", container.DumpRestore(name))
		_, err := os.Create(config.Agent.LxcPrefix + name + "/.start")
		log.Check(log.WarnLevel, "Creating start trigger", err)
	case false:
		log.Info("Creating container checkpoint")
		log.Check(log.ErrorLevel, "Creating container checkpoint", container.Dump(name, stop))
		if stop {
			log.Check(log.WarnLevel, "Removing start trigger", os.Remove(config.Agent.LxcPrefix+name+"/.start"))
		}
	}
}

// subutai-dev.criu dump -s --tree 2140 -D /var/snap/subutai-dev/common/lxc/m1/checkpoint --enable-external-masters --ext-mount-map auto --file-locks --ext-mount-map /opt:/var/snap/subutai-dev/common/lxc/m1/opt --ext-mount-map /home:/var/snap/subutai-dev/common/lxc/m1/home --ext-mount-map /var:/var/snap/subutai-dev/common/lxc/m1/var --empty-ns net
