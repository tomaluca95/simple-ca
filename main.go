package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/tomaluca95/simple-ca/internal/mainprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
	"github.com/tomaluca95/simple-ca/internal/webserver"
	"gopkg.in/yaml.v3"
)

const exitCodeOperationalFailure = 2

func fatalExit(format string, a ...any) {
	log.Printf("level=error "+format, a...)
	os.Exit(exitCodeOperationalFailure)
}

func main() {
	logger := &types.StdLogger{}
	ctx := context.Background()
	configFilename := "config.yml"
	if configFilenameOverride, overrideDone := os.LookupEnv("SIMPLE_CLI_CA_CONFIG_FILENAME"); overrideDone {
		configFilename = configFilenameOverride
	}
	configFile := types.ConfigFileType{}
	{
		configFileBytes, err := os.ReadFile(configFilename)
		if err != nil {
			fatalExit("msg=%q config_file=%q err=%v", "failed reading config file", configFilename, err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(configFileBytes))
		decoder.KnownFields(true)
		if err := decoder.Decode(&configFile); err != nil {
			fatalExit("msg=%q config_file=%q err=%v", "failed parsing config file", configFilename, err)
		}
	}

	if len(os.Args) == 1 {
		if err := mainprocess.RunWithConfigFileData(ctx, logger, configFile); err != nil {
			fatalExit("msg=%q err=%v", "main process failed", err)
		}
	} else if len(os.Args) == 2 && os.Args[1] == "http" {
		if configFile.HttpServer == nil {
			fatalExit("msg=%q", "missing http_server block")
		}
		netListen, err := net.Listen("tcp",
			fmt.Sprintf(
				"%s:%d",
				configFile.HttpServer.ListenAddress,
				configFile.HttpServer.ListenPort,
			),
		)
		if err != nil {
			fatalExit(
				"msg=%q listen_address=%q listen_port=%d err=%v",
				"failed opening HTTP listener",
				configFile.HttpServer.ListenAddress,
				configFile.HttpServer.ListenPort,
				err,
			)
		}
		defer netListen.Close()

		httpHandler, err := webserver.CreateHandler(ctx, logger, configFile)
		if err != nil {
			fatalExit("msg=%q err=%v", "failed creating HTTP handler", err)
		}

		if err := http.Serve(netListen, httpHandler); err != nil {
			fatalExit("msg=%q err=%v", "http server stopped with error", err)
		}
	} else {
		fatalExit("msg=%q args=%v", "invalid arguments", os.Args)
	}
}
