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
	portmap    = []byte("portmap")
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
		for _, b := range [][]byte{uuidmap, sshtunnels, containers, portmap} {
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

func (i *Instance) GetContainerByName(name string) (c map[string]string) {
	// c := make(map[string]string)
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			if b = b.Bucket([]byte(name)); b != nil {
				b.ForEach(func(kk, vv []byte) error {
					c[string(kk)] = string(vv)
					return nil
				})
			}
		}
		return nil
	})
	return c
}

func (i *Instance) GetContainerByVlan(vlan string) (list []string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			b.ForEach(func(k, v []byte) error {
				if c := b.Bucket(k); c != nil {
					c.ForEach(func(kk, vv []byte) error {
						if string(kk) == "vlan" && string(vv) == vlan {
							list = append(list, string(k))
						}
						return nil
					})
				}
				return nil
			})
		}
		return nil
	})
	return
}

func (i *Instance) PortMapSet(protocol, internal, external string, domain []string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			b, err = b.CreateBucketIfNotExists([]byte(protocol))
			if err != nil {
				return err
			}
			if protocol == "http" && len(domain) > 0 {
				b, err = b.CreateBucketIfNotExists([]byte(domain[0]))
				if err != nil {
					return err
				}
			}
			b, err = b.CreateBucketIfNotExists([]byte(external))
			if err != nil {
				return err
			}
			if err = b.Put([]byte(internal), []byte("w")); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (i *Instance) PortMapDelete(protocol, internal, external string, domain []string) (left int) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b := b.Bucket([]byte(protocol)); b != nil {
				if protocol == "http" && len(domain) > 0 {
					if len(internal) == 0 {
						b.DeleteBucket([]byte(domain[0]))
						return nil
					}
					b = b.Bucket([]byte(domain[0]))
				}
				if len(external) > 0 && len(internal) > 0 {
					if b = b.Bucket([]byte(external)); b != nil {
						left = b.Stats().KeyN
						if b.Get([]byte(internal)) != nil {
							b.Delete([]byte(internal))
							left--
						}
					}
				} else if len(external) > 0 {
					b.DeleteBucket([]byte(external))
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) PortInMap(protocol, external, internal string, domain []string) (res bool) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if protocol == "http" && len(domain) > 0 {
					if b = b.Bucket([]byte(domain[0])); b == nil {
						return nil
					}
				}
				if b = b.Bucket([]byte(external)); b != nil {
					if len(internal) > 0 && b.Get([]byte(internal)) == nil {
						return nil
					}
					res = true
				}
			}
		}
		return nil
	})
	return
}
