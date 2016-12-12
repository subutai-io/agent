package db

import (
	"strconv"

	"github.com/boltdb/bolt"

	"github.com/subutai-io/agent/config"
)

var (
	portmap = []byte("portmap")
	uuidmap = []byte("uuidmap")
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
		for _, b := range [][]byte{portmap, uuidmap} {
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

func (i *Instance) AddUuidEntry(name, uuid string) error {
	return i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(uuidmap); b != nil {
			return b.Put([]byte(uuid), []byte(name))
		}
		return nil
	})
}

func (i *Instance) DelUuidEntry(name string) error {
	return i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(uuidmap); b != nil {
			b.ForEach(func(k, v []byte) error {
				if string(v) == name {
					return b.Put(k, []byte("#"))
				}
				return nil
			})
		}
		return nil
	})
}

func (i *Instance) GetFreeUuid() (uuid []byte) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(uuidmap); b != nil {
			if b.Stats().KeyN == 0 {
				uuid = []byte("65536")
			} else {
				b.ForEach(func(k, v []byte) error {
					if string(v) == "#" {
						uuid = k
					}
					return nil
				})
			}
			if len(uuid) == 0 {
				uuid = []byte(strconv.Itoa(65536 + 65536*b.Stats().KeyN))
			}
		}
		return nil
	})
	return uuid
}
