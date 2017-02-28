package db

import (
	"strconv"

	"github.com/boltdb/bolt"

	"github.com/subutai-io/agent/config"
)

var (
	uuidmap    = []byte("uuidmap")
	sshtunnels = []byte("sshtunnels")
	containers = []byte("containers")
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
		for _, b := range [][]byte{uuidmap, sshtunnels, containers} {
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

func (i *Instance) GetUuidEntry(name string) string {
	var uuid []byte
	i.db.Update(func(tx *bolt.Tx) error {
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
			b.Put(uuid, []byte(name))
		}
		return nil
	})
	return string(uuid)
}

func (i *Instance) AddTunEntry(options map[string]string) error {
	return i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(sshtunnels); b != nil {
			if c, err := b.CreateBucketIfNotExists([]byte(options["pid"])); err == nil {
				for k, v := range options {
					if err := c.Put([]byte(k), []byte(v)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func (i *Instance) DelTunEntry(pid string) error {
	return i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(sshtunnels); b != nil {
			return b.DeleteBucket([]byte(pid))
		}
		return nil
	})
}

func (i *Instance) GetTunList() (list []map[string]string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(sshtunnels); b != nil {
			b.ForEach(func(k, v []byte) error {
				if c := b.Bucket([]byte(k)); c != nil {
					item := make(map[string]string)
					item["pid"] = string(k)
					c.ForEach(func(n, m []byte) error {
						item[string(n)] = string(m)
						return nil
					})
					list = append(list, item)
				}
				return nil
			})
			return nil
		}
		return nil
	})
	return list
}

// DiscoverySave stores information from auto discovery service in DB.
func (i *Instance) DiscoverySave(ip string) error {
	return i.db.Update(func(tx *bolt.Tx) error {
		if c, err := tx.CreateBucketIfNotExists([]byte("config")); err == nil {
			if err := c.Put([]byte("DiscoveredIP"), []byte(ip)); err != nil {
				return err
			}
		}
		return nil
	})
}

// DiscoveryLoad returns information from auto discovery service stored in DB.
func (i *Instance) DiscoveryLoad() (ip string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte("config")); b != nil {
			ip = string(b.Get([]byte("DiscoveredIP")))
		}
		return nil
	})
	return ip
}

func (i *Instance) ContainerAdd(name string, options map[string]string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			b, err = b.CreateBucketIfNotExists([]byte(name))
			if err != nil {
				return err
			}
			for k, v := range options {
				if err = b.Put([]byte(k), []byte(v)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) ContainerDel(name string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			if err = b.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (i *Instance) ContainerQuota(name, res, quota string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			if b = b.Bucket([]byte(name)); b != nil {
				b, err := b.CreateBucketIfNotExists([]byte("quota"))
				if err != nil {
					return err
				}
				if err = b.Put([]byte(res), []byte(quota)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return err
}
