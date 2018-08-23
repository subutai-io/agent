// Package connect purposed for initial data exchange between SS Management server and Subutai Agent daemon
package connect

//TODO remove hearbeat from registration
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
	"time"
	"net/http"
	"github.com/subutai-io/agent/agent/heartbeat"
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

var (
	client = utils.GetSecureClient()

	fingerprint string
)
//sendRegistrationRequest collecting connection request and sends to the Management server.
func sendRegistrationRequest(user, pass string) {
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

func IsConsoleReady() (status bool) {
	resp, err := client.Get("https://" + path.Join(config.ManagementIP) + ":8443/rest/v1/peer/ready")
	if err == nil {
		defer utils.Close(resp)
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

func CheckRegisterWithConsole() {
	for {

		//TODO if config.ManagementIP is wrong this line does not pass
		for !IsConsoleReady() {
			time.Sleep(time.Second * 10)
		}

		if fingerprint == "" {
			fingerprint = gpg.GetRhFingerprint()
			sendRegistrationRequest(config.Agent.GpgUser, config.Management.Secret)
		} else {
			doCheckConnection()
		}

		time.Sleep(time.Second * 10)
	}
}

func doCheckConnection() {
	resp, err := client.Get("https://" + path.Join(config.ManagementIP) + ":8444/rest/v1/agent/check/" + fingerprint)
	if err == nil {
		defer utils.Close(resp)
	}
	if err == nil && resp.StatusCode == http.StatusOK {
		log.Debug("Connection monitor check - success")
	} else {
		log.Debug("Connection monitor check - failed")
		sendRegistrationRequest(config.Agent.GpgUser, config.Management.Secret)
		heartbeat.ForceHeartBeat()

		//TODO connection is not reset if config.ManagementIP is wrong
		//reset config.ManagementIP to enable rediscovery
		if strings.TrimSpace(config.Management.Host) == "" {
			config.ManagementIP = ""
		}
	}
}
