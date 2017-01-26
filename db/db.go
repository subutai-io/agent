package db

import (
	"strconv"

	"github.com/boltdb/bolt"

	"github.com/subutai-io/agent/config"
)

var (
	portmap     = []byte("portmap")
	uuidmap     = []byte("uuidmap")
	sshtunnels  = []byte("sshtunnels")
	environment = []byte("environment")
)

type Instance struct {
	db *bolt.DB
}

type Environment struct {
	id struct {
		p2p        *bolt.Bucket
		containers *[]container
	}
}

type container struct {
	quota *bolt.Bucket
}

type p2p struct {
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
		for _, b := range [][]byte{portmap, uuidmap, sshtunnels, environment} {
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

func (i *Instance) GetUuidEntry() (uuid []byte) {
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

func (i *Instance) Environment(id string) (env Environment, err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(environment); b != nil {
			env.id, err = b.CreateBucketIfNotExists([]byte(id))
		}
		return nil
	})
	return env, err
}

func (env *Environment) P2P(dev, ip string) (err error) {
	if env.p2p, err = env.bucket.CreateBucketIfNotExists([]byte("p2p")); err == nil {
		env.p2p.Put([]byte("dev"), []byte(dev))
		env.p2p.Put([]byte("ip"), []byte(ip))
	}
	return err
}

func (env *Environment) Container(name string, args ...map[string]string) (err error) {
	if env.containers.b0ucket, err = env.bucket.CreateBucketIfNotExists([]byte("containers")); err == nil {
		env.containers.c, err = env.containers.CreateBucketIfNotExists([]byte(name))
		if err == nil {
			if len(args) != 0 {
				for k, v := range args[0] {
					container.Put([]byte(k), []byte(v))
				}
			}
		}
	}
	return err
}

// func (env *Environment) Quota() error {
// if quota, err := env.containers .CreateBucketIfNotExists(key); err == nil {
// }
// }
