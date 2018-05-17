package db

import (
	"strconv"

	"github.com/boltdb/bolt"

	"github.com/subutai-io/agent/config"
	"path"
	"time"
)

type Db struct {
}

var INSTANCE = Db{}

var (
	sshtunnels = []byte("sshtunnels")
	containers = []byte("containers")
	templates  = []byte("templates")
	portmap    = []byte("portmap")
)

func openDb(readOnly bool) (*bolt.DB, error) {
	boltDB, err := bolt.Open(path.Join(config.Agent.DataPrefix, "agent.db"),
		0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}

	return boltDB, nil
}

func (i *Db) AddTunEntry(options map[string]string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			var b *bolt.Bucket
			if b, err = tx.CreateBucketIfNotExists(sshtunnels); err == nil {
				if c, err := b.CreateBucketIfNotExists([]byte(options["pid"])); err == nil {
					for k, v := range options {
						if err := c.Put([]byte(k), []byte(v)); err != nil {
							return err
						}
					}
				}
			}
			return err
		})
	}
	return err
}

func (i *Db) DelTunEntry(pid string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			if b := tx.Bucket(sshtunnels); b != nil {
				return b.DeleteBucket([]byte(pid))
			}
			return nil
		})
	}
	return err
}

func (i *Db) GetTunList() (list []map[string]string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return list, err
}

// DiscoverySave stores information from auto discovery service in DB.
func (i *Db) DiscoverySave(ip string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			var b *bolt.Bucket
			if b, err = tx.CreateBucketIfNotExists([]byte("config")); err == nil {
				err = b.Put([]byte("DiscoveredIP"), []byte(ip))
			}
			return err
		})
	}
	return err
}

// DiscoveryLoad returns information from auto discovery service stored in DB.
func (i *Db) DiscoveryLoad() (ip string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket([]byte("config")); b != nil {
				ip = string(b.Get([]byte("DiscoveredIP")))
			}
			return nil
		})
	}
	return ip, err
}

func (i *Db) TemplateAdd(name string, options map[string]string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			var b *bolt.Bucket
			if b, err = tx.CreateBucketIfNotExists(templates); err == nil {
				if b, err = b.CreateBucketIfNotExists([]byte(name)); err == nil {
					for k, v := range options {
						if err = b.Put([]byte(k), []byte(v)); err != nil {
							return err
						}
					}
				}
			}
			return err
		})
	}
	return err
}

func (i *Db) TemplateDel(name string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		instance.Update(func(tx *bolt.Tx) error {
			if b := tx.Bucket(templates); b != nil {
				if err = b.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return err
}

func (i *Db) TemplateByName(name string) (c map[string]string, err error) {
	c = make(map[string]string)
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return c, err
}

func (i *Db) TemplateByKey(key, value string) (list []string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return list, err
}

func (i *Db) ContainerAdd(name string, options map[string]string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			var b *bolt.Bucket
			if b, err = tx.CreateBucketIfNotExists(containers); err == nil {
				if b, err = b.CreateBucketIfNotExists([]byte(name)); err == nil {
					for k, v := range options {
						if err = b.Put([]byte(k), []byte(v)); err != nil {
							return err
						}
					}
				}
			}
			return err
		})
	}
	return err
}

func (i *Db) ContainerDel(name string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			if b := tx.Bucket(containers); b != nil {
				if err = b.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return err
}

func (i *Db) ContainerMapping(name, protocol, external, domain, internal string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			if b := tx.Bucket(containers); b != nil {
				if b = b.Bucket([]byte(name)); b != nil {
					if b, err = b.CreateBucketIfNotExists([]byte("portmap")); err == nil {
						var n uint64
						if n, err = b.NextSequence(); err == nil {
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
			return err
		})
	}
	return err
}

func (i *Db) GetContainerMapping(name string) (list []map[string]string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return list, err
}

func (i *Db) ContainerList() (list []string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket(containers); b != nil {
				b.ForEach(func(k, v []byte) error {
					list = append(list, string(k))
					return nil
				})
			}
			return nil
		})
	}
	return list, err
}

func (i *Db) ContainerByName(name string) (c map[string]string, err error) {
	c = make(map[string]string)
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return c, err
}

func (i *Db) ContainerByKey(key, value string) (list []string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return list, err
}

func (i *Db) PortMapSet(protocol, external, domain, internal string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		return instance.Update(func(tx *bolt.Tx) error {
			var b *bolt.Bucket
			if b, err = tx.CreateBucketIfNotExists(portmap); err == nil {
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
			return err
		})
	}
	return err
}

func (i *Db) SetMapMethod(protocol, external, domain, policy string) (err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		instance.Update(func(tx *bolt.Tx) error {
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
	}
	return err
}

func (i *Db) GetMapMethod(protocol, external, domain string) (policy string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return policy, err
}

func (i *Db) PortMapDelete(protocol, external, domain, internal string) (left int, err error) {
	var instance *bolt.DB
	if instance, err = openDb(false); err == nil {
		defer instance.Close()
		instance.Update(func(tx *bolt.Tx) error {
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
	}
	return left, err
}

func (i *Db) PortInMap(protocol, external, domain, internal string) (res bool, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return res, err
}

func (i *Db) PortmapList(protocol string) (list []string, err error) {
	var instance *bolt.DB
	if instance, err = openDb(true); err == nil {
		defer instance.Close()
		instance.View(func(tx *bolt.Tx) error {
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
	}
	return list, err
}
