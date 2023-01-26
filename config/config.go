package config

type Subscription struct {
	Link          string `mapstructure:"link"`
	Select        string `mapstructure:"select" default:"first"`
	CacheLastNode bool   `mapstructure:"cache_last_node" default:"true"`
}
type Cache struct {
	Subscription CacheSubscription `mapstructure:"subscription"`
}
type CacheSubscription struct {
	LastNode string `mapstructure:"last_node"`
}
type Params struct {
	Node         string       `mapstructure:"node"`
	Subscription Subscription `mapstructure:"subscription"`

	Cache Cache `mapstructure:"cache"`

	NoUDP bool `mapstructure:"no_udp"`

	TestNode bool   `mapstructure:"test_node_before_use" default:"true"`
	TestURL  string `mapstructure:"test_url" default:"https://connectivitycheck.gstatic.com/generate_204"`
}

var ParamsObj Params
