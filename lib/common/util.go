package common

import (
	"fmt"
	"crypto/rand"
	"github.com/subutai-io/agent/log"
)

// Mac function generates random mac address for LXC containers
func Mac() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	log.Check(log.ErrorLevel, "Generating random mac", err)
	return fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5])
}
