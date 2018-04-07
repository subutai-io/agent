package discovery

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
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
)

type handler struct {
}

func (h handler) Tracef(f string, args ...interface{}) {}
func (h handler) Infof(f string, args ...interface{})  {}
func (h handler) Warnf(f string, args ...interface{})  { log.Debug("SSDP: " + fmt.Sprintf(f, args)) }
func (h handler) Errorf(f string, args ...interface{}) { log.Debug("SSDP: " + fmt.Sprintf(f, args)) }

func (h handler) Response(message gossdp.ResponseMessage) {
	//if strings.TrimSpace(config.Management.Fingerprint) == "" ||
	//	strings.EqualFold(strings.TrimSpace(config.Management.Fingerprint), strings.TrimSpace(message.DeviceId)) {
	//	save(message.Location)
	//}

	//config.Management.Fingerprint or config.Management.Host properties determine discovery
	////if both properties are set in config
	if strings.TrimSpace(config.Management.Fingerprint) != "" && strings.TrimSpace(config.Management.Host) != "" {
		//if both properties match then connect
		if strings.EqualFold(strings.TrimSpace(config.Management.Fingerprint), strings.TrimSpace(message.DeviceId)) &&
			strings.EqualFold(strings.TrimSpace(message.Location), strings.TrimSpace(config.Management.Host)) {

			save(message.Location)
		}
	} else
	//if fingerprint is set and matches then connect
	if strings.TrimSpace(config.Management.Fingerprint) != "" &&
		strings.EqualFold(strings.TrimSpace(config.Management.Fingerprint), strings.TrimSpace(message.DeviceId)) {
		save(message.Location)
	} else
	//if mgmt host is set and matches then connect
	if strings.TrimSpace(config.Management.Host) != "" &&
		strings.EqualFold(strings.TrimSpace(config.Management.Host), strings.TrimSpace(message.Location)) {

		save(message.Location)
	} else
	//if both properties are not set then connect to first found
	if strings.TrimSpace(config.Management.Fingerprint) == "" && strings.TrimSpace(config.Management.Host) == "" {
		save(message.Location)
	}
}

// ImportManagementKey adds GPG public key to local keyring to encrypt messages to Management server.
func ImportManagementKey() {
	if pk := getKey(); pk != nil {
		gpg.ImportPk(pk)
		config.Management.GpgUser = extractKeyID(pk)
	}
}

// Monitor provides service for auto discovery based on SSDP protocol.
// It starts SSDP server if management container active, otherwise it starts client for waiting another SSDP server.
func Monitor() {
	for {
		if container.State("management") == "RUNNING" {
			go server()
			save("10.10.10.1")
		} else {
			go client()
		}
		time.Sleep(30 * time.Second)
	}
}

func server() error {
	s, err := gossdp.NewSsdpWithLogger(nil, handler{})
	if err == nil {
		go s.Start()
		defer s.Stop()
		s.AdvertiseServer(gossdp.AdvertisableServer{
			ServiceType: "urn:" + os.Getenv("SNAP_NAME") + ":management:peer:5",
			DeviceUuid:  fingerprint(),
			Location:    net.GetIp(),
			MaxAge:      3600,
		})
		for len(fingerprint()) > 0 {
			time.Sleep(30 * time.Second)
		}
	}
	return err
}

func client() error {
	if len(config.Management.Host) > 6 {
		return nil
	}

	c, err := gossdp.NewSsdpClientWithLogger(handler{}, handler{})
	if err == nil {
		go c.Start()
		defer c.Stop()

		err = c.ListenFor("urn:" + os.Getenv("SNAP_NAME") + ":management:peer:5")
		time.Sleep(2 * time.Second)
	}
	return err
}

func fingerprint() string {
	client := utils.GetClient(config.Management.Allowinsecure, 5)
	resp, err := client.Get("https://10.10.10.1:8443/rest/v1/security/keyman/getpublickeyfingerprint")
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
	base, err := db.New()
	if err != nil {
		return
	}
	base.DiscoverySave(ip)
	base.Close()

	config.Management.Host = ip

	utils.ResetInfluxDbClient()
}

func getKey() []byte {
	client := utils.GetClient(config.Management.Allowinsecure, 5)
	resp, err := client.Get("https://" + config.Management.Host + ":" + config.Management.Port + config.Management.RestPublicKey)

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

func extractKeyID(k []byte) string {
	command := exec.Command("gpg1")
	stdin, err := command.StdinPipe()
	if err != nil {
		return ""
	}

	_, err = stdin.Write(k)
	log.Check(log.DebugLevel, "Writing to stdin pipe", err)
	log.Check(log.DebugLevel, "Closing stdin pipe", stdin.Close())
	out, err := command.Output()
	log.Check(log.WarnLevel, "Extracting ID from Key", err)

	if line := strings.Fields(string(out)); len(line) > 1 {
		if key := strings.Split(line[1], "/"); len(key) > 1 {
			return key[1]
		}
	}
	return ""
}
