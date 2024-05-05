package types

type ConfigFileType struct {
	DataDirectory string                              `yaml:"data_directory"`
	HttpServer    *HttpServerType                     `yaml:"http_server"`
	AllCaConfigs  map[string]CertificateAuthorityType `yaml:"all_ca_configs"`
}
