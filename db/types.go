package db

type Proxy struct {
	Id              int    `storm:"id,increment"`
	Protocol        string `storm:"index"`
	Port            int    `storm:"index"`
	Domain          string `storm:"index"`
	Tag             string `storm:"unique"`
	LoadBalancing   string
	Redirect80To443 bool
	SslBackend      bool
	IsLetsEncrypt   bool
}

type ProxiedServer struct {
	Id       int    `storm:"id,increment"`
	ProxyTag string `storm:"index"`
	Socket   string `storm:"index"`
}

type SshTunnel struct {
	Id           int    `storm:"id,increment"`
	Pid          int    `storm:"index"`
	LocalSocket  string `storm:"index"`
	RemoteSocket string
	Ttl          int
}
