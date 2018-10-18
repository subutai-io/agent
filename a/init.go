package a

import (
	"os"
	"github.com/subutai-io/agent/log"
)

func init() {
	if os.Getuid() != 0 {
		log.Error("Please run as root")
	}
}
