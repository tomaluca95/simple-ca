package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/tomaluca95/simple-ca/internal/mainprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
	"github.com/tomaluca95/simple-ca/internal/webserver"
	"gopkg.in/yaml.v3"
)

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
			panic(err)
		}
		if err := yaml.Unmarshal(configFileBytes, &configFile); err != nil {
			panic(err)
		}
	}

	if len(os.Args) == 1 {
		if err := mainprocess.RunWithConfigFileData(ctx, logger, configFile); err != nil {
			panic(err)
		}
	} else if len(os.Args) == 2 && os.Args[1] == "http" {
		if configFile.HttpServer == nil {
			panic(fmt.Errorf("missing http_server block"))
		}
		netListen, err := net.Listen("tcp",
			fmt.Sprintf(
				"%s:%d",
				configFile.HttpServer.ListenAddress,
				configFile.HttpServer.ListenPort,
			),
		)
		if err != nil {
			panic(err)
		}
		defer netListen.Close()

		httpHandler, err := webserver.CreateHandler(ctx, logger, configFile)
		if err != nil {
			panic(err)
		}

		if err := http.Serve(netListen, httpHandler); err != nil {
			panic(err)
		}
	} else {
		panic(fmt.Errorf("invalid arguments %v", os.Args))
	}
}
