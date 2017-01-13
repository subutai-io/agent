package discovery

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

const (
	port    = "56734"
	message = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
)

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
	udpAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:"+port)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		recvBuff := make([]byte, 15000)
		n, rmAddr, err := conn.ReadFromUDP(recvBuff)
		if err != nil {
			return err
		}
		fingerprint := getFingerprint()
		if fingerprint == nil {
			break
		}
		if string(recvBuff[:n]) == message || string(recvBuff[:n]) == string(fingerprint) {
			conn.WriteToUDP(fingerprint, rmAddr)
		}

	}
	return nil
}

func client() error {
	RemoteAddr, err := net.ResolveUDPAddr("udp", "255.255.255.255:"+port)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := message
	if len(config.Management.Fingerprint) > 0 {
		msg = config.Management.Fingerprint
	}
	_, err = conn.WriteToUDP([]byte(msg), RemoteAddr)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		buf := make([]byte, 15000)
		_, remAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		} else {
			save(remAddr.IP.String())
		}
	}
	return nil
}

func getFingerprint() []byte {
	client := &http.Client{Timeout: time.Second * 5}
	if config.Management.Allowinsecure {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second * 5}
	}
	resp, err := client.Get("https://10.10.10.1:8443/rest/v1/security/keyman/getpublickeyfingerprint")
	if log.Check(log.WarnLevel, "Getting Management host GPG fingerprint", err) {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		key, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			return key
		}
	}

	log.Warn("Failed to fetch GPG fingerprint from Management Server. Status Code " + strconv.Itoa(resp.StatusCode))
	return nil
}

func save(ip string) {
	if config.Management.Host != ip {
		ioutil.WriteFile("/var/lib/apps/subutai/current/agent.discovery.gcfg", []byte("[management]\nhost = "+ip+"\n\n[influxdb]\nserver = "+ip+"\n\n"), 0600)
	}
	config.Management.Host = ip
	config.Influxdb.Server = ip
}
