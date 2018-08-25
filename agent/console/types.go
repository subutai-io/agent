package console

import (
	"net/http"
	"github.com/subutai-io/agent/agent/util"
	"time"
)

// Container describes Subutai container with all required options for the Management server.
type Container struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Hostname   string  `json:"hostname"`
	Status     string  `json:"status,omitempty"`
	Arch       string  `json:"arch"`
	Interfaces []Iface `json:"interfaces"`
	Parent     string  `json:"templateName,omitempty"`
	Vlan       string  `json:"vlan,omitempty"`
	EnvId      string  `json:"environmentId,omitempty"`
	Pk         string  `json:"publicKey,omitempty"`
	Quota      Quota   `json:"quota,omitempty"`
}

//Quota describes container quota value.
type Quota struct {
	CPU  int `json:"cpu,omitempty"`
	RAM  int `json:"ram,omitempty"`
	Disk int `json:"disk,omitempty"`
}

type Iface struct {
	InterfaceName string `json:"interfaceName"`
	IP            string `json:"ip"`
}

type Console struct {
	fingerprint  string
	httpUtil     util.HttpUtil
	client       *http.Client
	secureClient *http.Client
}

func (c Console) Heartbeats() {
	for {

		if c.SendHeartBeat() == nil {
			time.Sleep(30 * time.Second)
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}

type rHost struct {
	Id           string      `json:"id"`
	Hostname     string      `json:"hostname"`
	Pk           string      `json:"publicKey"`
	Cert         string      `json:"cert"`
	Secret       string      `json:"secret"`
	Address      string      `json:"address"`
	Arch         string      `json:"arch"`
	InstanceType string      `json:"instanceType"`
	Containers   []Container `json:"hostInfos"`
}

//Response covers heartbeat date because of format required by Management server.
type response struct {
	Beat heartbeat `json:"response"`
}

//heartbeat describes JSON formated information that Agent sends to Management server.
type heartbeat struct {
	Type       string      `json:"type"`
	Hostname   string      `json:"hostname"`
	Address    string      `json:"address"`
	ID         string      `json:"id"`
	Arch       string      `json:"arch"`
	Instance   string      `json:"instance"`
	Containers []Container `json:"containers,omitempty"`
}
