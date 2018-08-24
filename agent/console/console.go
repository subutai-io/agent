package console

import (
	"github.com/subutai-io/agent/agent/util"
	"net/http"
	"github.com/subutai-io/agent/config"
	"path"
	"github.com/subutai-io/agent/lib/gpg"
	"io/ioutil"
	"github.com/pkg/errors"
	"fmt"
	"github.com/subutai-io/agent/agent/container"
	"os"
	"strings"
	"bytes"
	"encoding/json"
	"runtime"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/log"
	"net/url"
	"sync"
)

type Console struct {
	fingerprint  string
	httpUtil     util.HttpUtil
	client       *http.Client
	secureClient *http.Client
}

type rHost struct {
	Id           string                `json:"id"`
	Hostname     string                `json:"hostname"`
	Pk           string                `json:"publicKey"`
	Cert         string                `json:"cert"`
	Secret       string                `json:"secret"`
	Address      string                `json:"address"`
	Arch         string                `json:"arch"`
	InstanceType string                `json:"instanceType"`
	Containers   []container.Container `json:"hostInfos"`
}

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
}

var (
	//todo move variables to Console instance
	console      Console
	instanceType = utils.InstanceType()
	instanceArch = strings.ToUpper(runtime.GOARCH)
	mutex        sync.Mutex
	pool         []container.Container
)

func init() {
	httpUtil := util.GetUtil()
	sc, err := httpUtil.GetBiSslClient(30)
	log.Check(log.FatalLevel, "'Initializing Console connectivity", err)
	console = Console{httpUtil: httpUtil, client: httpUtil.GetClient(30), secureClient: sc, fingerprint: gpg.GetRhFingerprint()}
}

func GetConsole() Console {
	return console
}

//returns true if Console is ready to operate
//returns false if not approved or any error during checking status
func (c Console) IsReady() bool {
	resp, err := c.client.Get("https://" + path.Join(config.ManagementIP) + ":8443/rest/v1/peer/ready")
	if err == nil {
		defer c.httpUtil.Close(resp)
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	log.Warn("Console is not ready")
	return false
}

//returns true if Console has approved this RH registration
//returns false if not approved or any error during checking registration
func (c Console) IsRegistered() bool {
	resp, err := c.secureClient.Get("https://" + path.Join(config.ManagementIP) + ":8444/rest/v1/agent/check/" + c.fingerprint)
	if err == nil {
		defer c.httpUtil.Close(resp)
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	log.Warn("RH is not registered")

	return false
}

//sends registration request to Console
func (c Console) Register() error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	//todo check err returned from gpg/net when gpg/net is refactored
	rh, err := json.Marshal(rHost{
		Hostname:     hostname,
		Secret:       config.Management.Secret,
		Pk:           gpg.GetPk(config.Agent.GpgUser),
		Id:           gpg.GetFingerprint(config.Agent.GpgUser),
		Arch:         strings.ToUpper(runtime.GOARCH),
		Cert:         utils.PublicCert(),
		Address:      net.GetIp(),
		InstanceType: utils.InstanceType(),
		Containers:   container.Active(true),
	})
	if err != nil {
		return err
	}

	msg, err := gpg.EncryptWrapper(config.Agent.GpgUser, config.Management.GpgUser, rh)
	if err != nil {
		return err
	}

	resp, err := c.client.Post("https://"+path.Join(config.ManagementIP)+":8443/rest/v1/registration/public-key", "text/plain",
		bytes.NewBuffer(msg))
	if err == nil {
		defer c.httpUtil.Close(resp)
	} else {
		return err
	}

	return nil
}

func (c Console) GetFingerprint() (string, error) {
	resp, err := c.client.Get("https://" + path.Join(config.ManagementIP) + ":8443/rest/v1/security/keyman/getpublickeyfingerprint")
	if err == nil {
		defer c.httpUtil.Close(resp)
	} else {
		return "", err
	}

	if resp.StatusCode == 200 {
		fp, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			return string(fp), nil
		} else {
			return "", err
		}
	} else {
		return "", errors.New(fmt.Sprintf("Response status %d", resp.StatusCode))
	}
}

//sends heartbeat to Console
//todo check and return errors
func (c Console) SendHeartBeat() error {
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
		Containers: pool,
	}}
	jbeat, err := json.Marshal(&res)
	if log.Check(log.WarnLevel, "Marshaling heartbeat JSON", err) {
		return err
	}
	encryptedMessage, err := gpg.EncryptWrapper(config.Agent.GpgUser, config.Management.GpgUser, jbeat);
	if !log.Check(log.WarnLevel, "Encrypting message for Console", err) {
		message, err := json.Marshal(map[string]string{"hostId": gpg.GetRhFingerprint(), "response": string(encryptedMessage)})
		log.Check(log.WarnLevel, "Marshal response json", err)

		resp, err := utils.PostForm(c.secureClient, "https://"+path.Join(config.ManagementIP)+":8444/rest/v1/agent/heartbeat", url.Values{"heartbeat": {string(message)}})
		if !log.Check(log.WarnLevel, "Sending heartbeat: "+string(jbeat), err) {
			defer utils.Close(resp)

			if resp.StatusCode == http.StatusAccepted {
				return nil
			}
		}
	}

	return err
}

//import Console public gpg key to RH keyring
func (c Console) ImportPubKey() error {
	key, err := c.getPubKey()
	if err != nil {
		return err
	}

	err = gpg.ImportPk(key)
	if err != nil {
		return err
	}

	config.Management.GpgUser = gpg.ExtractKeyID(key)

	return nil
}

//fetches Console public GPG key
func (c Console) getPubKey() ([]byte, error) {
	resp, err := c.client.Get("https://" + path.Join(config.ManagementIP) + ":8443/rest/v1/security/keyman/getpublickeyring")

	if err == nil {
		defer c.httpUtil.Close(resp)
	} else {
		return nil, err
	}

	if resp.StatusCode == 200 {
		if key, err := ioutil.ReadAll(resp.Body); err == nil {
			return key, nil
		} else {
			return nil, err
		}
	} else {
		return nil, errors.New(fmt.Sprintf("Response status %d", resp.StatusCode))
	}
}

func (c Console) GetContainerNameByID(id string) string {
	for _, c := range pool {
		if c.ID == id {
			return c.Name
		}
	}
	return ""
}
