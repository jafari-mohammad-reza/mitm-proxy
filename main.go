package main

import (
	"log/slog"
)

func main() {
	conf, err := ReadConf()
	if err != nil {
		slog.Error("Failed to read config", "error", err)
	}
	logger, err := NewLogger(conf)
	if err != nil {
		slog.Error("Failed to initialize logger", "error", err)
	}
	server := NewProxyServer(conf, logger)
	if err := server.Start(); err != nil {
		logger.Error("Failed to start proxy server", err)
	}
}
