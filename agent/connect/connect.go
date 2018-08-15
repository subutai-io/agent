// Package connect purposed for initial data exchange between SS Management server and Subutai Agent daemon
package connect

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"

	"github.com/subutai-io/agent/agent/container"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/gpg"
	ovs "github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
	"path"
)

type rHost struct {
	UUID         string                `json:"id"`
	Hostname     string                `json:"hostname"`
	Pk           string                `json:"publicKey"`
	Cert         string                `json:"cert"`
	Secret       string                `json:"secret"`
	Address      string                `json:"address"`
	Arch         string                `json:"arch"`
	InstanceType string                `json:"instanceType"`
	Containers   []container.Container `json:"hostInfos"`
}

//Request collecting connection request and sends to the Management server.
func Request(user, pass string) {
	log.Debug("Connecting to " + config.ManagementIP + ":" + config.Management.Port)
	hostname, err := os.Hostname()
	log.Check(log.DebugLevel, "Getting Resource Host hostname", err)

	rh, err := json.Marshal(rHost{
		Hostname:     hostname,
		Secret:       pass,
		Pk:           gpg.GetPk(user),
		UUID:         gpg.GetFingerprint(user),
		Arch:         strings.ToUpper(runtime.GOARCH),
		Cert:         utils.PublicCert(),
		Address:      ovs.GetIp(),
		InstanceType: utils.InstanceType(),
		Containers:   container.Active(true),
	})
	log.Check(log.WarnLevel, "Marshal Resource host json: "+string(rh), err)

	client := utils.GetClient(config.Management.AllowInsecure, 30)
	msg, _ := gpg.EncryptWrapper(user, config.Management.GpgUser, rh)
	resp, err := client.Post("https://"+path.Join(config.ManagementIP)+":"+config.Management.Port+"/rest/v1/registration/public-key", "text/plain",
		bytes.NewBuffer(msg))

	if !log.Check(log.WarnLevel, "POSTing registration request to SS", err) {
		defer utils.Close(resp)
	}
}
