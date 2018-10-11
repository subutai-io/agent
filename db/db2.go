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
		log.Check(log.ErrorLevel, "Initializing database", db.Init(&PortMapping{}))
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

func GetAllMappings(protocol string) (list []string, err error) {
	var db *storm.DB
	db, err = getDb(true);
	if err != nil {
		return list, err
	}
	defer db.Close()

	var mappings [] PortMapping
	if protocol == "" {
		db.All(&mappings)
	} else {
		err = db.Find("Protocol", protocol, &mappings)
		if err != nil {
			return list, err
		}
	}

	for i := 0; i < len(mappings); i++ {
		mapping := mappings[i]

		line := mapping.Protocol + "\t" + mapping.ExternalSocket + "\t" + mapping.InternalSocket + "\t" + mapping.Domain

		list = append(list, line)
	}

	return list, err
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
