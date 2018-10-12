package db

type PortMapping struct {
	Id              int    `storm:"id,increment"`
	Protocol        string `storm:"index"`
	InternalSocket  string `storm:"index"`
	ExternalSocket  string `storm:"index"`
	Domain          string `storm:"index"`
	BalancingPolicy string
	SslBackend      bool
}

type SshTunnel struct {
	Id           int    `storm:"id,increment"`
	Pid          int    `storm:"index"`
	LocalSocket  string `storm:"index"`
	RemoteSocket string
	Ttl          int
}
