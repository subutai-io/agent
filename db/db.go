package db

import (
	"github.com/boltdb/bolt"

	"github.com/subutai-io/agent/config"
)

var (
	portmap = []byte("portmap")
)

type Instance struct {
	db *bolt.DB
}

func New() (*Instance, error) {
	boltDB, err := bolt.Open(config.Agent.DataPrefix+"agent.db", 0600, nil)
	if err != nil {
		return nil, err
	}

	if initdb(boltDB) != nil {
		return nil, err
	}
	return &Instance{db: boltDB}, nil
}

func initdb(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{portmap} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

func (i *Instance) Close() error {
	return i.db.Close()
}

func (i *Instance) WritePortMap(hostport, containerSocket string) error {
	return i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			return b.Put([]byte(hostport), []byte(containerSocket))
		}
		return nil
	})
}
