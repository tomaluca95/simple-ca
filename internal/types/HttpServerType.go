package types

type HttpServerType struct {
	ListenAddress string `yaml:"listen_address"`
	ListenPort    uint16 `yaml:"listen_port"`
}
