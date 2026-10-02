package types

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultHttpServerTimeout is the timeout used when http_server.timeout is not
// set.
const DefaultHttpServerTimeout = 5 * time.Second

type HttpServerType struct {
	ListenAddress string `yaml:"listen_address"`
	ListenPort    uint16 `yaml:"listen_port"`

	// Timeout bounds reading a request, writing its response, and how long a
	// connection may stay idle, and is also how long a shutdown waits for the
	// requests still in flight. Zero means DefaultHttpServerTimeout.
	Timeout time.Duration `yaml:"timeout"`
}

func (httpServer HttpServerType) Validate() []error {
	problems := []error{}

	// An empty address is handed to net.Listen as ":port", which binds every
	// interface the host has: a missing line in the config would silently
	// expose the signing endpoint, and with it the Authorization header, on
	// every network. Requiring a literal address makes the binding explicit;
	// the wildcards 0.0.0.0 and :: are still valid, but only when written out.
	if strings.TrimSpace(httpServer.ListenAddress) == "" {
		problems = append(problems, fmt.Errorf("%w: http_server.listen_address must be set", ErrInvalidConfig))
	} else if net.ParseIP(httpServer.ListenAddress) == nil {
		problems = append(problems, fmt.Errorf(
			"%w: http_server.listen_address %q is not a valid IPv4 or IPv6 address",
			ErrInvalidConfig, httpServer.ListenAddress,
		))
	}

	// Port 0 asks the kernel for an arbitrary free port, which binds somewhere
	// but tells no one where; the operator cannot reach a port it never saw.
	if httpServer.ListenPort == 0 {
		problems = append(problems, fmt.Errorf("%w: http_server.listen_port must not be 0", ErrInvalidConfig))
	}

	if httpServer.Timeout < 0 {
		problems = append(problems, fmt.Errorf("%w: http_server.timeout must not be negative", ErrInvalidConfig))
	}
	return problems
}

// TimeoutOrDefault returns the configured timeout, or the default one when it
// is not set.
func (httpServer HttpServerType) TimeoutOrDefault() time.Duration {
	if httpServer.Timeout == 0 {
		return DefaultHttpServerTimeout
	}
	return httpServer.Timeout
}
