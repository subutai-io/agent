package discovery

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/fromkeith/gossdp"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"path"
	"github.com/subutai-io/agent/lib/common"
)

type handler struct {
}

func (h handler) Tracef(f string, args ...interface{}) {}
func (h handler) Infof(f string, args ...interface{})  {}
func (h handler) Warnf(f string, args ...interface{})  { log.Debug("SSDP: " + fmt.Sprintf(f, args)) }
func (h handler) Errorf(f string, args ...interface{}) { log.Debug("SSDP: " + fmt.Sprintf(f, args)) }

func (h handler) Response(message gossdp.ResponseMessage) {

	log.Debug("Found server " + message.Location + "/" + message.DeviceId + "/" + message.Server)

	managementHostIp := config.Management.Host
	if managementHostIp == "10.10.10.1" {
		managementHostIp = ""
	}

	//config.Management.Fingerprint or managementHostIp properties determine discovery
	////if both properties are set in config
	if strings.TrimSpace(config.Management.Fingerprint) != "" && strings.TrimSpace(managementHostIp) != "" {
		//if both properties match then connect
		if strings.EqualFold(strings.TrimSpace(config.Management.Fingerprint), strings.TrimSpace(message.DeviceId)) &&
			strings.EqualFold(strings.TrimSpace(message.Location), strings.TrimSpace(managementHostIp)) {

			save(message.Location)
		}
	} else
	//if fingerprint is set and matches then connect
	if strings.TrimSpace(config.Management.Fingerprint) != "" &&
		strings.EqualFold(strings.TrimSpace(config.Management.Fingerprint), strings.TrimSpace(message.DeviceId)) {
		save(message.Location)
	} else
	//if mgmt host is set and matches then connect
	if strings.TrimSpace(managementHostIp) != "" &&
		strings.EqualFold(strings.TrimSpace(managementHostIp), strings.TrimSpace(message.Location)) {

		save(message.Location)
	} else
	//if both properties are not set then connect to first found
	if strings.TrimSpace(config.Management.Fingerprint) == "" && strings.TrimSpace(managementHostIp) == "" {
		save(message.Location)
	}
}

// ImportManagementKey adds GPG public key to local keyring to encrypt messages to Management server.
func ImportManagementKey() {
	if pk := getKey(); pk != nil {
		gpg.ImportPk(pk)
		config.Management.GpgUser = gpg.ExtractKeyID(pk)
	}
}

// Monitor provides service for auto discovery based on SSDP protocol.
// It starts SSDP server if management container active, otherwise it starts client for waiting another SSDP server.
func Monitor() {
	for {
		if container.State("management") == "RUNNING" {
			go common.RunNRecover(server)
		} else {
			go common.RunNRecover(client)
		}
		time.Sleep(30 * time.Second)
	}
}

var ssdpServerRunning bool

func server() {
	if ssdpServerRunning {
		return
	}

	ssdpServerRunning = true

	defer func() {
		ssdpServerRunning = false
	}()

	save("10.10.10.1")

	s, err := gossdp.NewSsdpWithLogger(nil, handler{})
	if err == nil {
		defer s.Stop()
		go common.RunNRecover(s.Start)
		address := "urn:subutai:management:peer:5"
		log.Debug("Launching SSDP server on " + address)
		s.AdvertiseServer(gossdp.AdvertisableServer{
			ServiceType: address,
			DeviceUuid:  fingerprint(config.Management.Host),
			Location:    net.GetIp(),
			MaxAge:      3600,
		})
		for len(fingerprint(config.Management.Host)) > 0 {
			time.Sleep(30 * time.Second)
		}
	} else {
		log.Warn(err)
	}
}

func client() {
	if len(strings.TrimSpace(config.Management.Host)) > 0 && len(fingerprint(config.Management.Host)) > 0 {
		return
	}

	c, err := gossdp.NewSsdpClientWithLogger(handler{}, handler{})
	if err == nil {
		defer c.Stop()
		go common.RunNRecover(c.Start)

		address := "urn:subutai:management:peer:5"
		log.Debug("Launching SSDP client on " + address)
		err = c.ListenFor(address)
		time.Sleep(10 * time.Second)
	} else {
		log.Warn(err)
	}
}

func fingerprint(ip string) string {
	client := utils.GetClient(config.Management.AllowInsecure, 30)
	resp, err := client.Get("https://" + ip + ":8443/rest/v1/security/keyman/getpublickeyfingerprint")
	if err == nil {
		defer utils.Close(resp)
	}

	if log.Check(log.WarnLevel, "Getting Management host GPG fingerprint", err) {
		return ""
	}

	if resp.StatusCode == 200 {
		key, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			return string(key)
		}
	}

	log.Warn("Failed to fetch GPG fingerprint from Management Server. Status Code " + strconv.Itoa(resp.StatusCode))
	return ""
}

func save(ip string) {
	log.Debug("Saving management host IP " + ip)

	db.INSTANCE.DiscoverySave(ip)

	config.Management.Host = ip
}

//TODO use single method
func getKey() []byte {
	client := utils.GetClient(config.Management.AllowInsecure, 30)
	resp, err := client.Get("https://" + path.Join(config.Management.Host) + ":" + config.Management.Port + config.Management.RestPublicKey)

	if err == nil {
		defer utils.Close(resp)
	}

	if log.Check(log.WarnLevel, "Getting Management host Public Key", err) {
		return nil
	}

	if resp.StatusCode == 200 {
		if key, err := ioutil.ReadAll(resp.Body); err == nil {
			return key
		}
	}

	log.Warn("Failed to fetch PK from Management Server. Status Code " + strconv.Itoa(resp.StatusCode))
	return nil
}
