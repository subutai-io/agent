package lib

import (
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/lib/template"
	"github.com/subutai-io/agent/log"
)

func LxcDestroy(name string) {
	if len(name) == 0 {
		log.Error("Please specify container or template name")
	}
	net.DelIface(container.GetConfigItem(config.Agent.LxcPrefix+name+"/config", "lxc.network.veth.pair"))
	container.Destroy(name)

	if name == "management" {
		template.MngStop()
		template.MngDel()
	}
}
