package lib

import (
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
)

func LxcDemote(name, ip, vlan string) {
	if !container.IsTemplate(name) {
		log.Error("Container " + name + " is not a template")
	}

	LxcNetwork(name, ip, vlan, false, false)
	fs.ReadOnly(name, false)
	container.SetContainerUid(name)
	log.Info(name + " demote succesfully")
}
