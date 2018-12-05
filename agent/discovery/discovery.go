package discovery

import (
	"fmt"
	"strings"
	"time"

	"github.com/fromkeith/gossdp"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/common"
	"github.com/subutai-io/agent/agent/console"
)

type handler struct {
}

func (h handler) Tracef(f string, args ...interface{}) {}
func (h handler) Infof(f string, args ...interface{})  {}
func (h handler) Warnf(f string, args ...interface{})  { log.Debug("SSDP: " + fmt.Sprintf(f, args)) }
func (h handler) Errorf(f string, args ...interface{}) { log.Debug("SSDP: " + fmt.Sprintf(f, args)) }

func (h handler) Response(message gossdp.ResponseMessage) {

	log.Debug("Found server " + message.Location + "/" + message.DeviceId + "/" + message.Server)

	managementHostIp := config.ManagementIP
	if managementHostIp == container.ManagementIp {
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

var consol console.Console

func init() {
	consol = console.GetConsole()
	loadManagementIp()
}

// Monitor provides service for auto discovery based on SSDP protocol.
// It starts SSDP server if management container active, otherwise it starts client for waiting another SSDP server.
func Monitor() {
	for {
		if container.State(container.Management) == container.Running {
			common.RunNRecover(server)
		} else {
			common.RunNRecover(client)
		}
		time.Sleep(time.Second)
	}
}

func server() {
	save(container.ManagementIp)

	s, err := gossdp.NewSsdpWithLogger(nil, handler{})
	if err == nil {
		defer s.Stop()
		go common.RunNRecover(s.Start)
		address := "urn:subutai:management:peer:5"
		log.Debug("Launching SSDP server on " + address)
		location := net.GetIp()
		fp, err := consol.GetFingerprint()
		if log.Check(log.WarnLevel, "Getting Console fingerprint", err) {
			return
		}
		s.AdvertiseServer(gossdp.AdvertisableServer{
			ServiceType: address,
			DeviceUuid:  fp,
			Location:    location,
			MaxAge:      3600,
		})

		//stay as ssdp server while registration with Console is valid and MH IP has not changed
		for consol.IsRegistered() && location == net.GetIp() {
			time.Sleep(10 * time.Second)
		}
	} else {
		log.Warn(err)
	}
}

func client() {
	//don't search new peers while registration with Console is valid
	for consol.IsRegistered() {
		if config.Management.GpgUser == "" {
			consol.ImportPubKey()
		}
		//if management is imported, return immediately
		if container.State(container.Management) == container.Running {
			return
		}
		time.Sleep(10 * time.Second)
	}

	//reset config.ManagementIP to enable auto rediscovery
	if strings.TrimSpace(config.Management.Host) == "" {
		log.Debug("Resetting MH IP")
		config.ManagementIP = ""
	} else {
		// check if peer is accessible by config.Management.Host
		fingerprint, err := consol.GetFingerprint()
		if err == nil {
			//check if fingerprint matches config.Management.Fingerprint
			if config.Management.Fingerprint == "" || config.Management.Fingerprint == fingerprint {
				//save ip
				save(config.Management.Host)
				return
			}
		}
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

func save(ip string) {
	ip = strings.TrimSpace(ip)

	log.Check(log.WarnLevel, "Saving Console IP "+ip, db.SaveDiscoveredIp(ip))

	config.ManagementIP = ip

	if !log.Check(log.WarnLevel, "Importing Console key", consol.ImportPubKey()) &&
		len(config.Management.GpgUser) > 0 {
		db.SaveMhGpgUsername(config.Management.GpgUser)
	}

	log.Check(log.WarnLevel, "Sending registration request to Console", consol.Register())
}

func loadManagementIp() {
	if strings.TrimSpace(config.Management.Host) == "" {
		ip, err := db.GetDiscoveredIp()
		if !log.Check(log.ErrorLevel, "Loading discovered Console ip from db", err) {
			config.ManagementIP = strings.TrimSpace(ip)
		}
	} else {
		config.ManagementIP = strings.TrimSpace(config.Management.Host)
	}
}
