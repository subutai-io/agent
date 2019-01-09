package db

type Proxy struct {
	Id             int    `storm:"id,increment"`
	Protocol       string `storm:"index"`
	Port           int    `storm:"index"`
	Domain         string `storm:"index"`
	Tag            string `storm:"unique"`
	LoadBalancing  string
	CertPath       string
	Redirect80Port bool
	SslBackend     bool
	Http2          bool
}

func (p Proxy) IsLE() bool {
	return p.Protocol == "https" && p.CertPath == ""
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

type Container struct {
	Id              int    `storm:"id,increment"`
	Name            string `storm:"index"`
	State           string
	Vlan            string
	EnvironmentId   string
	Gateway         string
	Ip              string
	Interface       string
	Uid             string
	Template        string
	TemplateOwner   string
	TemplateVersion string
	TemplateId      string
}
