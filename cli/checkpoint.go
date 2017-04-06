package cli

import (
	"os"
	"strconv"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
	lxc "gopkg.in/lxc/go-lxc.v2"
)

func Checkpoint(name, date string, restore, backup bool) {
	switch restore {
	case true:
		options := lxc.RestoreOptions{
			Directory: config.Agent.LxcPrefix + "/" + name + "/checkpoint",
			Verbose:   true,
		}
		if backup {
			log.Info("Restoring container data")
			RestoreContainer(name, date, name)
		}
		c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
		log.Check(log.ErrorLevel, "Creating container object", err)
		log.Info("Restoring container state")
		log.Check(log.ErrorLevel, "Restoring checkpoint", c.Restore(options))
		log.Info("Container state restored")

	case false:
		options := lxc.CheckpointOptions{
			Directory: config.Agent.LxcPrefix + "/" + name + "/checkpoint",
			Verbose:   true,
			Stop:      true,
		}
		c, err := lxc.NewContainer(name, config.Agent.LxcPrefix)
		log.Check(log.ErrorLevel, "Creating container object", err)
		log.Check(log.DebugLevel, "Removing autostart trigger", os.Remove(config.Agent.LxcPrefix+"/"+name+"/.start"))
		log.Info("Dumping container state")
		log.Check(log.ErrorLevel, "Creating checkpoint", c.Checkpoint(options))
		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		meta := bolt.ContainerByName(name)
		log.Check(log.WarnLevel, "Closing database", bolt.Close())
		uid, _ := strconv.Atoi(meta["uid"])
		log.Check(log.WarnLevel, "Chowning checkpoint",
			fs.ChownR(config.Agent.LxcPrefix+"/"+name+"/checkpoint", uid, uid))
		if backup {
			log.Info("Creating data backup")
			log.Info("Dump timestamp: " + BackupContainer(name, true, true))
		}
	}
}

// subutai-dev.criu dump -s --tree 2140 -D /var/snap/subutai-dev/common/lxc/m1/checkpoint --enable-external-masters --ext-mount-map auto --file-locks --ext-mount-map /opt:/var/snap/subutai-dev/common/lxc/m1/opt --ext-mount-map /home:/var/snap/subutai-dev/common/lxc/m1/home --ext-mount-map /var:/var/snap/subutai-dev/common/lxc/m1/var --empty-ns net
