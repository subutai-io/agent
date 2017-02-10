package discovery

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/fromkeith/gossdp"
	"github.com/subutai-io/agent/agent/monitor"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/net"
	"github.com/subutai-io/agent/log"
)

type handler struct {
}

func (h handler) Response(message gossdp.ResponseMessage) {
	if len(config.Management.Fingerprint) == 0 || config.Management.Fingerprint == message.DeviceId {
		save(message.Location)
	}
}

func Monitor() {
	for {
		if container.State("management") == "RUNNING" {
			go server()
			save("10.10.10.1")
		} else {
			go client()
		}
		time.Sleep(5 * time.Second)
	}
}

func server() error {
	s, err := gossdp.NewSsdp(nil)
	if err == nil {
		go s.Start()
		defer s.Stop()
		s.AdvertiseServer(gossdp.AdvertisableServer{
			ServiceType: "urn:subutai:management:peer:4",
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
	c, err := gossdp.NewSsdpClient(handler{})
	if err == nil {
		go c.Start()
		defer c.Stop()

		err = c.ListenFor("urn:subutai:management:peer:4")
		time.Sleep(2 * time.Second)
	}
	return err
}

func fingerprint() string {
	client := &http.Client{Timeout: time.Second * 5}
	if config.Management.Allowinsecure {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second * 5}
	}
	resp, err := client.Get("https://10.10.10.1:8443/rest/v1/security/keyman/getpublickeyfingerprint")
	if log.Check(log.WarnLevel, "Getting Management host GPG fingerprint", err) {
		return ""
	}
	defer resp.Body.Close()

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
	config.Influxdb.Server = ip
	if config.Management.Host != ip {
		ioutil.WriteFile(config.Agent.DataPrefix+"agent.gcfg.discovery", []byte("[management]\nhost = "+ip+"\n\n[influxdb]\nserver = "+ip+"\n\n"), 0600)
		monitor.InitInfluxdb()
	}
	config.Management.Host = ip
}
