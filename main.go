package main

import "log/slog"

func main() {
	conf, err := ReadConf()
	if err != nil {
		slog.Error("Failed to read config", "error", err)
	}
	logger, err := NewLogger(conf)
	if err != nil {
		slog.Error("Failed to initialize logger", "error", err)
	}
	certHandler := NewCertHandler(conf, logger)
	err = certHandler.Init()
	if err != nil {
		logger.Error("Failed to initialize certificate handler", err)
	}
	server := NewProxyServer(conf, logger, certHandler)
	if err := server.Start(); err != nil {
		logger.Error("Failed to start proxy server", err)
	}
}
