package main

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

type ILogger interface {
	Info(msg string, args ...any)
	Error(msg string, err error)
}
type Logger struct {
	conf     *Conf
	mu       sync.Mutex
	infoFile *os.File
	errFile  *os.File
}

func NewLogger(conf *Conf) (*Logger, error) {
	fmt.Printf("conf.Log.InfoPath: %v\n", conf.Log.InfoPath)
	if _, err := os.Stat(conf.Log.InfoPath); os.IsNotExist(err) {
		fmt.Printf("Creating log file: %s\n", conf.Log.InfoPath)
		if err := os.WriteFile(conf.Log.InfoPath, nil, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
	}
	if _, err := os.Stat(conf.Log.ErrorPath); os.IsNotExist(err) {
		fmt.Printf("Creating error file: %s\n", conf.Log.InfoPath)
		if err := os.WriteFile(conf.Log.InfoPath, nil, 0755); err != nil {
			return nil, fmt.Errorf("failed to create error directory: %w", err)
		}
	}
	infoFile, err := os.OpenFile(conf.Log.InfoPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	errFile, err := os.OpenFile(conf.Log.ErrorPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{conf: conf, mu: sync.Mutex{}, infoFile: infoFile, errFile: errFile}, nil
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

func (l *Logger) writeLog(entry LogEntry) {
	var file *os.File
	switch entry.Level {
	case "info":
		file = l.infoFile
	case "error":
		file = l.errFile
	default:
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := file.WriteString(fmt.Sprintf("%s [%s] %s\n", entry.Timestamp, entry.Level, entry.Message))
	if err != nil {
		slog.Error("Failed to write log entry", "error", err)
		return
	}
	if err := file.Sync(); err != nil {
		slog.Error("Failed to sync log file", "error", err)
		return
	}
	slog.Info("Log entry written", "level", entry.Level, "message", entry.Message)
}
func (l *Logger) Info(msg string, args ...any) {
	slog.Info(msg, args...)
	l.writeLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "info",
		Message:   msg + " " + fmt.Sprint(args...),
	})
}
func (l *Logger) Error(msg string, err error) {
	slog.Error(msg, "error", err)
	l.writeLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "error",
		Message:   msg + ": " + err.Error()})
}
