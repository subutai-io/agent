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

func init() {
	if !fs.FileExists(dbPath) {
		db, err := storm.Open(dbFilePath, storm.BoltOptions(0600, &bolt.Options{ReadOnly: false}))
		log.Check(log.ErrorLevel, "Creating database", err)
		defer db.Close()

		//init db structs
		log.Check(log.ErrorLevel, "Initializing ssh tunnels storage", db.Init(&SshTunnel{}))
		log.Check(log.ErrorLevel, "Initializing proxy storage", db.Init(&Proxy{}))
		log.Check(log.ErrorLevel, "Initializing proxied servers storage", db.Init(&ProxiedServer{}))
	}
}

func getDb(readOnly bool) (*storm.DB, error) {
	boltDB, err := storm.Open(dbFilePath,
		//workaround: seems storm has bug related with read-only mode, it still tries to open db as read-write
		storm.BoltOptions(0600, &bolt.Options{Timeout: 15 * time.Second, ReadOnly: false}))
	//storm.BoltOptions(0600, &bolt.Options{Timeout: 15 * time.Second, ReadOnly: readOnly}))

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

func RemoveProxy(proxy *Proxy) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(proxy)
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

func RemoveProxiedServer(proxiedServer *ProxiedServer) (err error) {
	var db *storm.DB
	db, err = getDb(false);
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(proxiedServer)
}

func FindProxyByTag(tag string) (proxy *Proxy, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return nil, err
	}
	defer db.Close()

	result := Proxy{}

	err = db.One("Tag", tag, &result)

	if err != nil && err == storm.ErrNotFound {
		return nil, nil
	}

	return &result, err
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

	if err != nil && err == storm.ErrNotFound {
		err = nil
	}

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

	if err != nil && err == storm.ErrNotFound {
		err = nil
	}

	return servers, err
}

//<<<<<<<Proxy

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

	result := SshTunnel{}
	err = db.One("LocalSocket", localSocket, &result)
	if err != nil && err == storm.ErrNotFound {
		return nil, nil
	}

	return &result, err
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
