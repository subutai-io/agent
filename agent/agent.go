// Package agent is a Subutai Agent daemon written in Golang whose main task is to receive commands from the Subutai Social management server and execute them on Resource Hosts.
// Behind such a seemingly simple task are complex procedures like bidirectional ssl communication, gpg message encryption, different health and security checks, etc.
package agent

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/subutai-io/agent/agent/alert"
	"github.com/subutai-io/agent/agent/connect"
	"github.com/subutai-io/agent/agent/container"
	"github.com/subutai-io/agent/agent/discovery"
	"github.com/subutai-io/agent/agent/executer"
	"github.com/subutai-io/agent/agent/monitor"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/log"
	"path"
	"github.com/subutai-io/agent/agent/heartbeat"
	"github.com/subutai-io/agent/cli"
)

var (
	client *http.Client
)

func initAgent() {

	client = utils.GetSecureClient()
}

//Start Subutai Agent daemon, all required goroutines and keep working during all life cycle.
func Start() {
	initAgent()

	setupHttpServer()

	//SSDP discovery for secondary RHs
	go discovery.Monitor()

	//metrics
	go monitor.Collect()

	go connect.CheckRegisterWithConsole()

	go alert.Processing()

	//restart containers that got stopped not by user
	go container.StateRestore()

	for {

		if heartbeat.HeartBeat() {
			time.Sleep(30 * time.Second)
		} else {
			time.Sleep(5 * time.Second)
		}

		cli.CheckSshTunnels()

		for !connect.IsConsoleReady() {
			time.Sleep(time.Second * 10)
		}
	}
}

//todo move to executer
//COMMAND EXECUTION>>>

func execute(rsp executer.EncRequest) {
	var req executer.Request
	var md, contName, pub, keyring string

	if rsp.HostID == gpg.GetRhFingerprint() {
		md = gpg.DecryptWrapper(rsp.Request)
	} else {
		contName = heartbeat.GetContainerNameByID(rsp.HostID)
		if contName == "" {
			heartbeat.ForceHeartBeat()
			contName = heartbeat.GetContainerNameByID(rsp.HostID)
			if contName == "" {
				return
			}
		}

		pub = path.Join(config.Agent.LxcPrefix, contName, "public.pub")
		keyring = path.Join(config.Agent.LxcPrefix, contName, "secret.sec")
		log.Info("Getting public keyring", "keyring", keyring)
		md = gpg.DecryptWrapper(rsp.Request, keyring, pub)
	}

	if log.Check(log.WarnLevel, "Decrypting request", json.Unmarshal([]byte(md), &req.Request)) {
		return
	}

	//create channels for stdout and stderr
	sOut := make(chan executer.ResponseOptions)
	if rsp.HostID == gpg.GetRhFingerprint() {
		go executer.ExecHost(req.Request, sOut)
	} else {
		go executer.AttachContainer(contName, req.Request, sOut)
	}

	for sOut != nil {
		if elem, ok := <-sOut; ok {
			resp := executer.Response{ResponseOpts: elem}
			jsonR, err := json.Marshal(resp)
			log.Check(log.WarnLevel, "Marshal response", err)

			var payload []byte
			if rsp.HostID == gpg.GetRhFingerprint() {
				payload, err = gpg.EncryptWrapper(config.Agent.GpgUser, config.Management.GpgUser, jsonR)
			} else {
				payload, err = gpg.EncryptWrapper(contName, config.Management.GpgUser, jsonR, pub, keyring)
			}
			if err == nil && len(payload) > 0 {
				message, err := json.Marshal(map[string]string{"hostId": elem.ID, "response": string(payload)})
				log.Check(log.WarnLevel, "Marshal response json "+elem.CommandID, err)
				go sendResponse(message, time.Now().Add(time.Second*time.Duration(req.Request.Timeout)))
			}
		} else {
			sOut = nil
		}
	}
	go heartbeat.HeartBeat()
}

func sendResponse(msg []byte, deadline time.Time) {
	resp, err := postForm("https://"+path.Join(config.ManagementIP)+":8444/rest/v1/agent/response", url.Values{"response": {string(msg)}})
	if !log.Check(log.WarnLevel, "Sending response "+string(msg), err) {
		defer utils.Close(resp)
		if resp.StatusCode == http.StatusAccepted {
			return
		}
	}

	if deadline.After(time.Now()) {
		time.Sleep(time.Second * 5)
		go sendResponse(msg, deadline)
	}

}

func command() {
	var rsp []executer.EncRequest

	resp, err := client.Get("https://" + path.Join(config.ManagementIP) + ":8444/rest/v1/agent/requests/" + gpg.GetRhFingerprint())

	if err == nil {
		defer utils.Close(resp)
	}

	if log.Check(log.WarnLevel, "Getting requests", err) {
		return
	}
	if resp.StatusCode == http.StatusNoContent {
		return
	}

	data, err := ioutil.ReadAll(resp.Body)
	if !log.Check(log.WarnLevel, "Reading body", err) {
		log.Check(log.WarnLevel, "Unmarshal payload", json.Unmarshal(data, &rsp))

		for _, request := range rsp {
			go execute(request)
		}
	}
}

//<<<COMMAND EXECUTION

//todo move to separate file
//HTTP server >>>>
var mux map[string]func(http.ResponseWriter, *http.Request)

type myHandler struct{}

func (*myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := mux[r.URL.String()]; ok {
		h(w, r)
		return
	}

	w.WriteHeader(http.StatusForbidden)
}

func setupHttpServer() {
	srv := &http.Server{
		Addr:              ":7070",
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		Handler:           &myHandler{},
	}
	mux = make(map[string]func(http.ResponseWriter, *http.Request))
	mux["/trigger"] = triggerHandler
	mux["/ping"] = pingHandler
	mux["/heartbeat"] = heartbeatHandler
	go srv.ListenAndServe()
}

func pingHandler(rw http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && strings.Split(request.RemoteAddr, ":")[0] == config.ManagementIP {
		rw.WriteHeader(http.StatusOK)
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}

func triggerHandler(rw http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPost && strings.Split(request.RemoteAddr, ":")[0] == config.ManagementIP {
		rw.WriteHeader(http.StatusAccepted)
		go command()
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}

func heartbeatHandler(rw http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && strings.Split(request.RemoteAddr, ":")[0] == config.ManagementIP {
		rw.WriteHeader(http.StatusOK)
		go heartbeat.ForceHeartBeat()
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}

//<<<HTTP server

func postForm(url string, data url.Values) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(req)
}
