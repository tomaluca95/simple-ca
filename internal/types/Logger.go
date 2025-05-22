package types

import (
	"log"
)

type Logger interface {
	Debug(format string, a ...any)
}

type StdLogger struct {
}

func (l *StdLogger) Debug(format string, a ...any) {
	log.Printf(format, a...)
}
