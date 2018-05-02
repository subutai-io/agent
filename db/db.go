package db

import (
	"strconv"

	"github.com/boltdb/bolt"

	"github.com/subutai-io/agent/config"
	"path"
)

var (
	uuidmap    = []byte("uuidmap")
	sshtunnels = []byte("sshtunnels")
	containers = []byte("containers")
	templates  = []byte("templates")
	portmap    = []byte("portmap")
)

type Instance struct {
	db *bolt.DB
}

func New() (*Instance, error) {
	boltDB, err := bolt.Open(path.Join(config.Agent.DataPrefix, "agent.db"), 0600, nil)
	if err != nil {
		return nil, err
	}

	if err = initdb(boltDB); err != nil {
		boltDB.Close()
		return nil, err
	}

	return &Instance{db: boltDB}, nil
}

func initdb(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{uuidmap, sshtunnels, containers, templates, portmap} {
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

func (i *Instance) TemplateAdd(name string, options map[string]string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(templates); b != nil {
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

func (i *Instance) TemplateDel(name string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(templates); b != nil {
			if err = b.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (i *Instance) TemplateByName(name string) map[string]string {
	c := make(map[string]string)
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(templates); b != nil {
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

func (i *Instance) TemplateByKey(key, value string) (list []string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(templates); b != nil {
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

func (i *Instance) ContainerMapping(name, protocol, external, domain, internal string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			if b = b.Bucket([]byte(name)); b != nil {
				if b, err = b.CreateBucketIfNotExists([]byte("portmap")); err == nil {
					if n, err := b.NextSequence(); err == nil {
						if b, err = b.CreateBucketIfNotExists([]byte(strconv.Itoa(int(n)))); err == nil {
							b.Put([]byte("protocol"), []byte(protocol))
							b.Put([]byte("external"), []byte(external))
							b.Put([]byte("domain"), []byte(domain))
							b.Put([]byte("internal"), []byte(internal))
						}
					}
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) GetContainerMapping(name string) (list []map[string]string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			if b = b.Bucket([]byte(name)); b != nil {
				if b = b.Bucket([]byte("portmap")); b != nil {
					b.ForEach(func(k, v []byte) error {
						l := make(map[string]string)
						if c := b.Bucket(k); c != nil {
							c.ForEach(func(kk, vv []byte) error {
								l[string(kk)] = string(vv)
								return nil
							})
						}
						list = append(list, l)
						return nil
					})
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) ContainerList() (list []string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(containers); b != nil {
			b.ForEach(func(k, v []byte) error {
				list = append(list, string(k))
				return nil
			})
		}
		return nil
	})
	return
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

func (i *Instance) PortMapSet(protocol, external, domain, internal string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b, err = b.CreateBucketIfNotExists([]byte(protocol)); err == nil {
				if b, err = b.CreateBucketIfNotExists([]byte(external)); err == nil {
					if b, err = b.CreateBucketIfNotExists([]byte(domain)); err == nil {
						if b, err = b.CreateBucketIfNotExists([]byte(internal)); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) SetMapMethod(protocol, external, domain, policy string) (err error) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if b = b.Bucket([]byte(external)); b != nil {
					if b = b.Bucket([]byte(domain)); b != nil {
						return b.Put([]byte("policy"), []byte(policy))
					}
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) GetMapMethod(protocol, external, domain string) (policy string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if b = b.Bucket([]byte(external)); b != nil {
					if b = b.Bucket([]byte(domain)); b != nil {
						policy = string(b.Get([]byte("policy")))
					}
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) PortMapDelete(protocol, external, domain, internal string) (left int) {
	i.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b := b.Bucket([]byte(protocol)); b != nil {
				if len(domain) > 0 {
					if b = b.Bucket([]byte(external)); b != nil {
						if len(internal) > 0 {
							if b = b.Bucket([]byte(domain)); b != nil {
								b.DeleteBucket([]byte(internal))
								left = b.Stats().BucketN - 2
							}
						} else {
							b.DeleteBucket([]byte(domain))
							left = b.Stats().BucketN - 2
						}
					}
				} else {
					b.DeleteBucket([]byte(external))
					left = b.Stats().BucketN - 2
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) PortInMap(protocol, external, domain, internal string) (res bool) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				if b = b.Bucket([]byte(external)); b != nil {
					if len(domain) > 0 {
						if b = b.Bucket([]byte(domain)); b != nil {
							if len(internal) > 0 {
								if b = b.Bucket([]byte(internal)); b != nil {
									res = true
								}
							} else {
								res = true
							}
						}
					} else {
						res = true
					}
				}
			}
		}
		return nil
	})
	return
}

func (i *Instance) PortmapList(protocol string) (list []string) {
	i.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(portmap); b != nil {
			if b = b.Bucket([]byte(protocol)); b != nil {
				b.ForEach(func(k, v []byte) error {
					if c := b.Bucket(k); c != nil {
						c.ForEach(func(kk, vv []byte) error {
							if d := c.Bucket(kk); d != nil {
								d.ForEach(func(kkk, vvv []byte) error {
									if d.Bucket(kkk) != nil {
										if line := protocol + "\t" + string(k) + "\t" + string(kkk); len(line) > 0 {
											if protocol == "http" || protocol == "https" {
												line = line + "\t" + string(kk)
											}
											list = append(list, line)
										}
									}
									return nil
								})
							}
							return nil
						})
					}
					return nil
				})
			}
		}
		return nil
	})
	return
}
