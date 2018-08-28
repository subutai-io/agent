// Subutai Agent daemon receives commands from the Subutai Console
// and executes them on Resource Hosts also using own CLI commands.
// Also Agent collects hosts metrics and performs other various tasks.
package agent

import (
	"net/http"
	"strings"
	"time"

	"github.com/subutai-io/agent/agent/container"
	"github.com/subutai-io/agent/agent/discovery"
	"github.com/subutai-io/agent/agent/monitor"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/cli"
	"github.com/subutai-io/agent/agent/console"
	"github.com/subutai-io/agent/log"
	"strconv"
	"github.com/subutai-io/agent/agent/util"
	"path"
)

var (
	consol console.Console
)

func initAgent() {
	consol = console.GetConsole()
}

//starts Subutai Agent daemon
func Start() {

	initAgent()

	//serve REST endpoints used by Console
	setupHttpServer()

	//search for peer or enable secondary RHs to find it
	go discovery.Monitor()

	//restart containers that got stopped not by user
	go container.StateRestore()

	//wait till Console is loaded
	for !consol.IsReady() {
		time.Sleep(time.Second * 3)
	}

	//wait till RH gets registered with Console
	for !consol.IsRegistered() {
		time.Sleep(time.Second * 5)
	}

	//below routines should start only when registration with Console is established
	go monitor.Collect()

	//start sending periodic heartbeats to Console
	go consol.Heartbeats()

	//todo refactor below
	for {
		cli.CheckSshTunnels()
		time.Sleep(30 * time.Second)
	}
}

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
	mux["/test"] = testHandler
	go srv.ListenAndServe()
}

func pingHandler(rw http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && strings.Split(request.RemoteAddr, ":")[0] == config.ManagementIP {
		rw.WriteHeader(http.StatusOK)
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}

func heartbeatHandler(rw http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && strings.Split(request.RemoteAddr, ":")[0] == config.ManagementIP {
		rw.WriteHeader(http.StatusOK)
		go consol.SendHeartBeat()
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}

func triggerHandler(rw http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPost && strings.Split(request.RemoteAddr, ":")[0] == config.ManagementIP {
		rw.WriteHeader(http.StatusAccepted)
		go consol.ExecuteConsoleCommands()
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}
func testHandler(rw http.ResponseWriter, request *http.Request) {
	log.Warn("TEST READY" + strconv.FormatBool(consol.IsRegistered()))
	clnt, _ := util.GetUtil().GetSecureClient(30)

	resp, err := clnt.Get("https://" + path.Join(config.ManagementIP) + ":8444/rest/v1/agent/check/" + consol.Fingerprint)
	if err == nil {
		defer util.GetUtil().Close(resp)
		if resp.StatusCode == http.StatusOK {
			log.Warn("TEST READY2 true")
			return
		}
	}

	log.Warn("TEST READY2 false")
}

//<<<HTTP server
