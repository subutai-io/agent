package cli

import (
	"github.com/subutai-io/agent/agent/console"
	"github.com/subutai-io/agent/agent/vars"
	"net/http"
	"github.com/subutai-io/agent/log"
)

var (
	consol console.Console
)

func init() {
	consol = console.GetConsole()
}

func sendHeartbeat() {
	if consol.IsRegistered() {
		//trigger heartbeat via REST to agent
		resp, err := http.Get("http://localhost:" + vars.DAEMON_PORT + "/heartbeat")
		if !log.Check(log.WarnLevel, "Triggering heartbeat", err) {
			consol.Close(resp)
		}
	}
}
