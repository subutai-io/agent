package db

import (
	"bytes"
	"strconv"

	"github.com/boltdb/bolt"

	"strings"

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

func (i *Instance) ContainerByName(name string) map[string]string {
	c := make(map[string]string)
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

func (i *Instance) ContainerByKey(key, value string) (list []string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			b.ForEach(func(k, v []byte) error {
				if c := b.Bucket(k); c != nil {
					c.ForEach(func(kk, vv []byte) error {
						if string(kk) == key && string(vv) == value {
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

func (i *Instance) PortMapSet(protocol, internal, external string, ops map[string]string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			b, err = b.CreateBucketIfNotExists([]byte(protocol))
			if err == nil {
				b, err = b.CreateBucketIfNotExists([]byte(external))
				if err == nil {
					b, err = b.CreateBucketIfNotExists([]byte(internal))
					for k, v := range ops {
						b.Put([]byte(k), []byte(v))
					}
				}
			}
			return err
		}
		return nil
	})
	return
}

func (i *Instance) SetMapMethod(protocol, external, policy string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if b = b.Bucket([]byte(external)); b != nil {
					return b.Put([]byte("policy"), []byte(policy))
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) GetMapMethod(protocol, external string) (policy string) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if b = b.Bucket([]byte(external)); b != nil {
					policy = string(b.Get([]byte("policy")))
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) ExtPorts(protocol, internal string) (list []string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				b.ForEach(func(k, v []byte) error {
					if c := b.Bucket(k); c != nil {
						if kk, _ := c.Cursor().Seek([]byte(internal + ":")); kk != nil {
							list = append(list, string(k))
						}
					}
					return nil
				})
			}
		}
		return nil
	})
	return
}
func (i *Instance) PortMapDelete(protocol, internal, external string) (left int) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b := b.Bucket([]byte(protocol)); b != nil {
				if len(external) > 0 && len(internal) > 0 {
					if b = b.Bucket([]byte(external)); b != nil {
						left = b.Stats().BucketN - 1
						if !strings.Contains(internal, ":") {
							c := b.Cursor()
							for k, _ := c.Seek([]byte(internal + ":")); k != nil && bytes.HasPrefix(k, []byte(internal+":")); k, _ = c.Next() {
								b.DeleteBucket(k)
								left--
							}
						} else if b.Bucket([]byte(internal)) != nil {
							b.DeleteBucket([]byte(internal))
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

func (i *Instance) PortInMap(protocol, external, internal string) (res bool) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if b = b.Bucket([]byte(external)); b != nil {
					if len(internal) == 0 {
						res = true
						return nil
					} else if !strings.Contains(internal, ":") {
						b.ForEach(func(k, v []byte) error {
							if strings.Contains(string(k), internal+":") {
								res = true
							}
							return nil
						})
					} else if b.Bucket([]byte(internal)) != nil {
						res = true
						return nil
					}
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) PortmapList(protocol string) (list []string) {
	var line, domain string
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				b.ForEach(func(k, v []byte) error {
					if c := b.Bucket(k); c != nil {
						c.ForEach(func(kk, vv []byte) error {
							if protocol == "http" || protocol == "https" {
								if d := c.Bucket(kk); d != nil {
									domain = string(d.Get([]byte("domain")))
								}
							}
							line = protocol + "\t" + string(k) + "\t" + string(kk) + "\t" + domain
							return nil
						})
					}
					return nil
				})
				if len(line) > 0 {
					list = append(list, line)
				}
			}
		}
		return nil
	})
	return
}
