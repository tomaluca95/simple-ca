package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/tomaluca95/simple-ca/internal/mainprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
	"github.com/tomaluca95/simple-ca/internal/webserver"
	"gopkg.in/yaml.v3"
)

const exitCodeOperationalFailure = 2

// buildSlogHandler returns the program-wide text handler, honoring the
// log_level from the config file. The context-tracing wrapper makes every
// record pick up request_id when one is carried by the context.
func buildSlogHandler(logLevel string) slog.Handler {
	level, _ := types.ParseLogLevel(logLevel)
	return types.NewLogHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}),
	)
}

func fatalExit(message string, args ...any) {
	slog.Error(message, args...)
	os.Exit(exitCodeOperationalFailure)
}

func main() {
	// Default level until the config file is read; a failed config read or
	// parse is logged with it.
	slog.SetDefault(slog.New(buildSlogHandler("")))

	configFilename := "config.yml"
	if configFilenameOverride, overrideDone := os.LookupEnv("SIMPLE_CLI_CA_CONFIG_FILENAME"); overrideDone {
		configFilename = configFilenameOverride
	}
	configFile := types.ConfigFileType{}
	{
		configFileBytes, err := os.ReadFile(configFilename)
		if err != nil {
			fatalExit("failed reading config file", "config_file", configFilename, "err", err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(configFileBytes))
		decoder.KnownFields(true)
		if err := decoder.Decode(&configFile); err != nil {
			fatalExit("failed parsing config file", "config_file", configFilename, "err", err)
		}
	}

	slog.SetDefault(slog.New(buildSlogHandler(configFile.LogLevel)))
	logger := types.NewStdLogger(slog.Default())
	ctx := context.Background()

	if len(os.Args) == 1 {
		if err := mainprocess.RunWithConfigFileData(ctx, logger, configFile); err != nil {
			fatalExit("main process failed", "err", err)
		}
	} else if len(os.Args) == 2 && os.Args[1] == "http" {
		if configFile.HttpServer == nil {
			fatalExit("missing http_server block")
		}
		if problems := configFile.HttpServer.Validate(); len(problems) > 0 {
			fatalExit("invalid http_server configuration", "err", errors.Join(problems...))
		}
		netListen, err := net.Listen("tcp",
			net.JoinHostPort(
				configFile.HttpServer.ListenAddress,
				strconv.Itoa(int(configFile.HttpServer.ListenPort)),
			),
		)
		if err != nil {
			fatalExit(
				"failed opening HTTP listener",
				"listen_address", configFile.HttpServer.ListenAddress,
				"listen_port", configFile.HttpServer.ListenPort,
				"err", err,
			)
		}
		defer netListen.Close()

		// SIGINT and SIGTERM stop the accept loop, the requests still in flight
		// and the periodic CRL refresh, so a sign request is never cut in half
		// and no refresh lands after the server has stopped.
		signalCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stopSignals()

		httpHandler, err := webserver.CreateHandler(signalCtx, logger, configFile)
		if err != nil {
			fatalExit("failed creating HTTP handler", "err", err)
		}

		httpServerTimeout := configFile.HttpServer.TimeoutOrDefault()
		httpServer := &http.Server{
			Handler:           httpHandler,
			ReadHeaderTimeout: httpServerTimeout,
			ReadTimeout:       httpServerTimeout,
			WriteTimeout:      httpServerTimeout,
			IdleTimeout:       httpServerTimeout,
			// The request line is a short path plus a serial of at most 40
			// characters; the 1MB default header budget only invites a client
			// to spend memory and log space per request.
			MaxHeaderBytes: 16 * 1024,
		}

		serveErr := make(chan error, 1)
		go func() {
			serveErr <- httpServer.Serve(netListen)
		}()

		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fatalExit("http server stopped with error", "err", err)
			}
		case <-signalCtx.Done():
			logger.InfoContext(ctx, "shutting down the http server", "graceful_shutdown_timeout", httpServerTimeout)
			shutdownCtx, cancelShutdown := context.WithTimeout(ctx, httpServerTimeout)
			defer cancelShutdown()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				// Requests that did not finish in time are cut off: there is
				// nothing left to wait for.
				_ = httpServer.Close()
				fatalExit("failed to shut down the http server gracefully", "graceful_shutdown_timeout", httpServerTimeout, "err", err)
			}
			logger.InfoContext(ctx, "http server stopped")
		}
	} else {
		fatalExit("invalid arguments", "args", os.Args)
	}
}
