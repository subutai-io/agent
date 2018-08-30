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
	"github.com/subutai-io/agent/agent/executer"
	"time"
	"github.com/subutai-io/agent/db"
	cont "github.com/subutai-io/agent/lib/container"
	"github.com/wunderlist/ttlcache"
	"strconv"
)

var (
	console Console
	//todo move variables to Console instance
	instanceType          = utils.InstanceType()
	instanceArch          = strings.ToUpper(runtime.GOARCH)
	heartbeatLock         sync.Mutex
	checkRegistrationLock sync.Mutex
	pool                  []Container
	cache                 *ttlcache.Cache
)

func init() {
	httpUtil := util.GetUtil()
	sc, err := httpUtil.GetSecureClient(30)
	log.Check(log.FatalLevel, "'Initializing Console connectivity", err)
	cache = utils.GetCache(time.Minute * 30)
	console = Console{httpUtil: httpUtil, client: httpUtil.GetClient(30), secureClient: sc, fingerprint: gpg.GetRhFingerprint()}
}

func GetConsole() Console {
	return console
}

func (c Console) Heartbeats() {
	for {
		if c.IsRegistered() {
			if c.SendHeartBeat(false) == nil {
				time.Sleep(30 * time.Second)
			} else {
				time.Sleep(5 * time.Second)
			}
		} else {
			time.Sleep(10 * time.Second)
		}
	}
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
	theUrl := "https://" + path.Join(config.ManagementIP) + ":8444/rest/v1/agent/check/" + c.fingerprint
	log.Debug("Checking registration with Console " + theUrl)
	resp, err := c.secureClient.Get(theUrl)
	if err == nil {
		defer c.httpUtil.Close(resp)
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	log.Warn("RH is not registered")

	checkRegistrationLock.Lock()
	defer checkRegistrationLock.Unlock()
	//recreate secure client to exclude issue with SSL
	c.secureClient, err = c.httpUtil.GetSecureClient(30)
	log.Check(log.FatalLevel, "Recreating secure client", err)

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
		Containers:   containers(true),
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

var lastHeartbeatTime time.Time
var lastHeartbeat []byte
//sends heartbeat to Console
//todo check and return errors
func (c Console) SendHeartBeat(force bool) error {
	heartbeatLock.Lock()
	defer heartbeatLock.Unlock()

	//dont send heartbeat if less than 5 seconds passed since last sending
	if !force && time.Since(lastHeartbeatTime) < time.Second*5 {
		return nil
	}

	pool = containers(false)
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
	heartbeat, err := json.Marshal(&res)
	if log.Check(log.WarnLevel, "Marshaling heartbeat JSON", err) {
		return err
	}

	//dont send heartbeat if nothing changed in its content
	if !force && string(heartbeat) == string(lastHeartbeat) {
		return nil
	}

	encryptedMessage, err := gpg.EncryptWrapper(config.Agent.GpgUser, config.Management.GpgUser, heartbeat)
	if !log.Check(log.WarnLevel, "Encrypting message for Console", err) {
		message, err := json.Marshal(map[string]string{"hostId": gpg.GetRhFingerprint(), "response": string(encryptedMessage)})
		log.Check(log.WarnLevel, "Marshal response json", err)

		resp, err := postForm(c.secureClient, "https://"+path.Join(config.ManagementIP)+":8444/rest/v1/agent/heartbeat", url.Values{"heartbeat": {string(message)}})
		if !log.Check(log.WarnLevel, "Sending heartbeat: "+string(heartbeat), err) {
			defer utils.Close(resp)

			if resp.StatusCode == http.StatusAccepted {
				lastHeartbeatTime = time.Now()
				lastHeartbeat = heartbeat
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

func (c Console) ExecuteConsoleCommands() {
	commands := c.getCommands()
	for _, cmd := range commands {
		go c.execute(cmd)
	}
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

//returns container name by container id
func (c Console) getContainerNameByID(id string) string {
	thePool := pool
	for _, c := range thePool {
		if c.ID == id {
			return c.Name
		}
	}

	return ""
}

//fetch commands to execute from Console
func (c Console) getCommands() []executer.EncRequest {
	var rsp []executer.EncRequest

	theUrl := "https://" + path.Join(config.ManagementIP) + ":8444/rest/v1/agent/requests/" + gpg.GetRhFingerprint()

	resp, err := c.secureClient.Get(theUrl)
	if err == nil {
		defer utils.Close(resp)
	}

	if log.Check(log.WarnLevel, "Fetching commands from Console", err) {
		return rsp
	}

	if resp.StatusCode == http.StatusNoContent {
		return rsp
	}

	data, err := ioutil.ReadAll(resp.Body)
	if log.Check(log.WarnLevel, "Reading commands from Console", err) {
		return rsp
	}

	if log.Check(log.WarnLevel, "Parsing commands from Console", json.Unmarshal(data, &rsp)) {
		return rsp
	}

	return rsp
}

//send a single command execution result to Console
func (c Console) sendResponse(msg []byte, deadline time.Time) {
	resp, err := postForm(c.secureClient, "https://"+path.Join(config.ManagementIP)+":8444/rest/v1/agent/response", url.Values{"response": {string(msg)}})
	if !log.Check(log.WarnLevel, "Sending response "+string(msg), err) {
		defer utils.Close(resp)
		if resp.StatusCode == http.StatusAccepted {
			return
		}
	}

	//retry sending a response
	if deadline.After(time.Now()) {
		time.Sleep(time.Second * 5)
		go c.sendResponse(msg, deadline)
	}
}

func (c Console) execute(cmd executer.EncRequest) {
	executer.Execute(cmd, c.sendResponse, c.getContainerNameByID(cmd.HostID))
	c.SendHeartBeat(false)
}

// containers provides list of active Subutai containers.
func containers(details bool) []Container {
	var contArr []Container

	for _, c := range cont.Containers() {
		hostname, err := ioutil.ReadFile(path.Join(config.Agent.LxcPrefix, c, "/rootfs/etc/hostname"))
		if err != nil {
			continue
		}
		configPath := path.Join(config.Agent.LxcPrefix, c, "config")

		if meta, err := db.INSTANCE.ContainerByName(c); err == nil {

			vlan := meta["vlan"]
			envId := meta["environment"]
			ip := meta["ip"]

			aContainer := Container{
				Name:     c,
				Hostname: strings.TrimSpace(string(hostname)),
				Status:   cont.State(c),
				Vlan:     vlan,
				EnvId:    envId,
			}

			aContainer.Interfaces = interfaces(c, ip)

			//cacheable properties>>>

			aContainer.ID = utils.GetFromCacheOrCalculate(cache, c+"_fingerprint", func() string {
				return gpg.GetFingerprint(c)
			})

			aContainer.Arch = utils.GetFromCacheOrCalculate(cache, c+"_arch", func() string {
				return strings.ToUpper(cont.GetConfigItem(configPath, "lxc.arch"))
			})

			aContainer.Parent = utils.GetFromCacheOrCalculate(cache, c+"_parent", func() string {
				return cont.GetConfigItem(configPath, "subutai.parent")
			})

			quotaRam := utils.GetFromCacheOrCalculate(cache, c+"_quota_ram", func() string {
				return strconv.Itoa(cont.QuotaRAM(c, ""))
			})
			aContainer.Quota.RAM, _ = strconv.Atoi(quotaRam)

			quotaCpu := utils.GetFromCacheOrCalculate(cache, c+"_quota_cpu", func() string {
				return strconv.Itoa(cont.QuotaCPU(c, ""))
			})
			aContainer.Quota.CPU, _ = strconv.Atoi(quotaCpu)

			quotaDisk := utils.GetFromCacheOrCalculate(cache, c+"_quota_disk", func() string {
				return strconv.Itoa(cont.QuotaDisk(c, ""))
			})
			aContainer.Quota.Disk, _ = strconv.Atoi(quotaDisk)

			//<<<cacheable properties

			if details {
				aContainer.Pk = gpg.GetContainerPk(c)
			}

			contArr = append(contArr, aContainer)

		}
	}
	return contArr
}

//this should be done together with Console changes
func interfaces(name string, staticIp string) []Iface {

	iface := new(Iface)

	iface.InterfaceName = cont.ContainerDefaultIface

	if staticIp != "" {
		iface.IP = staticIp
	} else {
		iface.IP = utils.GetFromCacheOrCalculate(cache, name+"_ip", func() string {
			return cont.GetIp(name)
		})
	}

	return []Iface{*iface}
}

func postForm(client *http.Client, url string, data url.Values) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(req)
}
