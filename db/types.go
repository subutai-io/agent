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
