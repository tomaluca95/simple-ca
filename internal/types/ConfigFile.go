package types

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

type ConfigFileType struct {
	LogLevel      string                              `yaml:"log_level"`
	DataDirectory string                              `yaml:"data_directory"`
	HttpServer    *HttpServerType                     `yaml:"http_server"`
	AllCaConfigs  map[string]CertificateAuthorityType `yaml:"all_ca_configs"`
}

// ParseLogLevel maps the config log_level value to a slog level. An empty
// value means info.
func ParseLogLevel(logLevel string) (slog.Level, error) {
	switch strings.TrimSpace(logLevel) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "":
		return slog.LevelInfo, nil
	default:
		return slog.LevelInfo, fmt.Errorf("%w: log_level %q is not one of debug, info, warn, error", ErrInvalidConfig, logLevel)
	}
}

// Validate returns nil, or one joined error per problem found in the whole
// configuration, so a broken config is reported at once instead of failing CA
// by CA while loading.
func (configFile ConfigFileType) Validate() error {
	allProblems := []error{}
	if _, err := ParseLogLevel(configFile.LogLevel); err != nil {
		allProblems = append(allProblems, err)
	}
	if strings.TrimSpace(configFile.DataDirectory) == "" {
		allProblems = append(allProblems, fmt.Errorf("%w: data_directory must be set", ErrInvalidConfig))
	}
	if configFile.HttpServer != nil {
		allProblems = append(allProblems, configFile.HttpServer.Validate()...)
	}
	for caId, caConfig := range configFile.AllCaConfigs {
		for _, problem := range caConfig.Validate() {
			allProblems = append(allProblems, fmt.Errorf("CA %q: %w", caId, problem))
		}
	}
	return errors.Join(allProblems...)
}
