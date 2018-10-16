package db

import (
	"github.com/asdine/storm"
	"path"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/fs"
	"time"
	bolt "go.etcd.io/bbolt"
	"github.com/asdine/storm/q"
	"fmt"
)

var (
	dbFilePath = path.Join(config.Agent.DataPrefix, "agent.db")
)
/*TODO rules:
1. Check for existing mappings only in db. DB must be the single place of authority
2. For config files just write what is inside db, thus overwriting the existing file upon need.
This way we dont care if configuration reside in separate files or single file
*/

func init() {
	if !fs.FileExists(dbPath) {
		db, err := storm.Open(dbFilePath, storm.BoltOptions(0600, &bolt.Options{ReadOnly: false}))
		log.Check(log.ErrorLevel, "Creating database", err)
		defer db.Close()
		//init PortMapping struct
		log.Check(log.ErrorLevel, "Initializing port mappings storage", db.Init(&PortMapping{}))
		//init SshTunnel struct
		log.Check(log.ErrorLevel, "Initializing ssh tunnels storage", db.Init(&SshTunnel{}))
		log.Check(log.ErrorLevel, "Initializing ssh tunnels storage", db.Init(&Proxy{}))
		log.Check(log.ErrorLevel, "Initializing ssh tunnels storage", db.Init(&ProxiedServer{}))

	}
}

func getDb(readOnly bool) (*storm.DB, error) {
	boltDB, err := storm.Open(dbFilePath,
		storm.BoltOptions(0600, &bolt.Options{Timeout: 15 * time.Second, ReadOnly: readOnly}))

	if err != nil {
		return nil, err
	}

	return boltDB, nil
}

//Proxy>>>>>>>

func SaveProxy(proxy *Proxy) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Save(proxy)
}

func SaveProxiedServer(proxiedServer *ProxiedServer) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Save(proxiedServer)
}
func RemoveProxiedServer(proxiedServer ProxiedServer) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(&proxiedServer)
}

func FindProxyByTag(tag string) (proxy *Proxy, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.One("Tag", tag, &proxy)
	if err != nil {
		return nil, err
	}

	return
}

func FindProxies(protocol, domain string, port int) (proxies []Proxy, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var matchers []q.Matcher

	if protocol != "" {
		matchers = append(matchers, q.Eq("Protocol", protocol))
	}

	if domain != "" {
		matchers = append(matchers, q.Eq("Domain", domain))
	}

	if port > 0 {
		matchers = append(matchers, q.Eq("Port", port))
	}

	err = db.Select(matchers...).Find(&proxies)

	return proxies, err
}

func FindProxiedServers(tag, socket string) (servers []ProxiedServer, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var matchers []q.Matcher

	if tag != "" {
		matchers = append(matchers, q.Eq("ProxyTag", tag))
	}

	if socket != "" {
		matchers = append(matchers, q.Eq("Socket", socket))
	}

	err = db.Select(matchers...).Find(&servers)

	return servers, err
}

//<<<<<<<Proxy

//Port Mappings >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
func GetAllMappings(protocol string) (mappings []PortMapping, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return
	}
	defer db.Close()

	if protocol == "" {
		db.All(&mappings)
	} else {
		err = db.Find("Protocol", protocol, &mappings)
		if err != nil {
			return
		}
	}

	return mappings, nil
}

func SaveMapping(mapping *PortMapping) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Save(mapping)
}

func RemoveMapping(mapping PortMapping) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(&mapping)
}

func FindMappings(protocol, socketExt, socketInt, domain string) (mappings []PortMapping, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var matchers []q.Matcher

	if protocol != "" {
		matchers = append(matchers, q.Eq("Protocol", protocol))
	}

	if socketInt != "" {
		matchers = append(matchers, q.Eq("InternalSocket", socketInt))
	}

	if socketExt != "" {
		matchers = append(matchers, q.Eq("ExternalSocket", socketExt))
	}

	if domain != "" {
		matchers = append(matchers, q.Eq("Domain", domain))
	}

	err = db.Select(matchers...).Find(&mappings)

	return mappings, err
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Port Mappings

// Ssh tunnels >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

func SaveTunnel(tunnel *SshTunnel) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Save(tunnel)
}

func UpdateTunnel(tunnel *SshTunnel) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(tunnel)
}

func FindTunnelByLocalSocket(localSocket string) (tunnel *SshTunnel, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.One("LocalSocket", localSocket, &tunnel)
	if err != nil {
		return nil, err
	}

	return
}

func GetAllTunnels() (tunnels []SshTunnel, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return
	}
	defer db.Close()

	db.All(&tunnels)

	return tunnels, nil
}

func FindTunnelsByPid(pid int) (tunnels []SshTunnel, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.Find("Pid", pid, &tunnels)

	return
}

func RemoveTunnelsByPid(pid int) error {
	tunnels, err := FindTunnelsByPid(pid)
	if err != nil {
		return err
	}

	for i := 0; i < len(tunnels); i++ {
		log.Check(log.WarnLevel, fmt.Sprintf("Removing tunnel %v", tunnels[i]), RemoveTunnel(tunnels[i]))
	}

	return nil
}

func RemoveTunnel(tunnel SshTunnel) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(&tunnel)
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Ssh tunnels
