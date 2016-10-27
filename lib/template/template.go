// Packag template works with template deployment, configuration and initialisation
package template

import (
	"crypto/rand"
	"fmt"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
)

// Install deploys downloaded and unpacked templates to the system
func Install(parent, child string) {
	delta := map[string][]string{
		child + "/deltas/rootfs.delta": {parent + "/rootfs", child},
		child + "/deltas/home.delta":   {parent + "/home", child},
		child + "/deltas/opt.delta":    {parent + "/opt", child},
		child + "/deltas/var.delta":    {parent + "/var", child},
	}

	fs.SubvolumeCreate(config.Agent.LxcPrefix + child)

	p := true
	if parent == child || parent == "" {
		p = false
	}

	for delta, path := range delta {
		fs.Receive(config.Agent.LxcPrefix+path[0], config.Agent.LxcPrefix+path[1], delta, p)
	}

	for _, file := range []string{"config", "fstab", "packages"} {
		fs.Copy(config.Agent.LxcPrefix+"tmpdir/"+child+"/"+file, config.Agent.LxcPrefix+child+"/"+file)
	}
}

// Mac function generates random mac address for LXC containers
func Mac() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	log.Check(log.ErrorLevel, "Generating random mac", err)
	return fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5])
}
