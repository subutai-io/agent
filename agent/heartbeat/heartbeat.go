package heartbeat

import (
	"time"
	"os"
	"github.com/subutai-io/agent/agent/alert"
	"github.com/subutai-io/agent/lib/gpg"
	"net/url"
	"sync"
	"github.com/subutai-io/agent/agent/container"
	"net/http"
	"github.com/subutai-io/agent/lib/net"
	"encoding/json"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/config"
	"path"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/agent/discovery"
	"strings"
	"runtime"
)

//Response covers heartbeat date because of format required by Management server.
type response struct {
	Beat heartbeat `json:"response"`
}

//heartbeat describes JSON formated information that Agent sends to Management server.
type heartbeat struct {
	Type       string                `json:"type"`
	Hostname   string                `json:"hostname"`
	Address    string                `json:"address"`
	ID         string                `json:"id"`
	Arch       string                `json:"arch"`
	Instance   string                `json:"instance"`
	Containers []container.Container `json:"containers,omitempty"`
	Alert      []alert.Load          `json:"alert,omitempty"`
}

var (
	mutex             sync.Mutex
	lastHeartbeat     []byte
	client            *http.Client
	instanceType      string
	instanceArch      string
	lastHeartbeatTime time.Time
	pool              []container.Container
)

func init() {
	instanceType = utils.InstanceType()
	instanceArch = strings.ToUpper(runtime.GOARCH)
	client = utils.GetSecureClient()
}

//send heartbeat not more than once in 5 sec
func HeartBeat() bool {
	if len(lastHeartbeat) > 0 && time.Since(lastHeartbeatTime) < time.Second*5 {
		return false
	}
	return sendHeartbeat()
}

//send heartbeat immediately
func ForceHeartBeat() bool {
	lastHeartbeat = []byte{}
	return sendHeartbeat()
}

func sendHeartbeat() bool {
	mutex.Lock()
	defer mutex.Unlock()

	pool = container.Active(false)
	hostname, err := os.Hostname()
	log.Check(log.DebugLevel, "Obtaining RH hostname", err)
	res := response{Beat: heartbeat{
		Type:       "HEARTBEAT",
		Hostname:   hostname,
		Address:    net.GetIp(),
		ID:         gpg.GetRhFingerprint(),
		Arch:       instanceArch,
		Instance:   instanceType,
		Containers: alert.Quota(pool),
		Alert:      alert.Current(pool),
	}}
	jbeat, err := json.Marshal(&res)
	log.Check(log.WarnLevel, "Marshaling heartbeat JSON", err)
	lastHeartbeatTime = time.Now()
	if string(jbeat) == string(lastHeartbeat) {
		return true
	}
	lastHeartbeat = jbeat

	if encryptedMessage, err := gpg.EncryptWrapper(config.Agent.GpgUser, config.Management.GpgUser, jbeat); err == nil {
		message, err := json.Marshal(map[string]string{"hostId": gpg.GetRhFingerprint(), "response": string(encryptedMessage)})
		log.Check(log.WarnLevel, "Marshal response json", err)

		resp, err := client.PostForm("https://"+path.Join(config.ManagementIP)+":8444/rest/v1/agent/heartbeat", url.Values{"heartbeat": {string(message)}})
		if !log.Check(log.WarnLevel, "Sending heartbeat: "+string(jbeat), err) {
			defer utils.Close(resp)

			if resp.StatusCode == http.StatusAccepted {
				return true
			}
		}
	}
	//try to import mgmt key
	go discovery.ImportManagementKey()
	lastHeartbeat = []byte{}
	return false
}

func GetContainerNameByID(id string) string {
	for _, c := range pool {
		if c.ID == id {
			return c.Name
		}
	}
	return ""
}
