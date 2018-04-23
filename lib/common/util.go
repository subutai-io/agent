package common

import (
	"fmt"
	"crypto/rand"
	"github.com/subutai-io/agent/log"
	"strings"
	"subutai/lxc"
	"path"
	"github.com/subutai-io/agent/config"
)

// Mac function generates random mac address for LXC containers
func Mac() string {

	usedMacs := make(map[string]bool)
	for _, cont := range lxc.Containers() {
		cfg, err := GetConfig(path.Join(config.Agent.LxcPrefix, cont, "config"))
		//skip error
		if err == nil {
			usedMacs[cfg.GetParam("lxc.network.hwaddr")] = true
		}
	}

	buf := make([]byte, 6)

	_, err := rand.Read(buf)
	log.Check(log.ErrorLevel, "Generating random mac", err)

	mac := fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5]);
	for usedMacs[mac] {

		_, err := rand.Read(buf)
		log.Check(log.ErrorLevel, "Generating random mac", err)

		mac = fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5]);
	}

	return mac
}

func Splitter(s string, splits string) []string {
	m := make(map[rune]int)
	for _, r := range splits {
		m[r] = 1
	}

	splitter := func(r rune) bool {
		return m[r] == 1
	}

	return strings.FieldsFunc(s, splitter)
}
