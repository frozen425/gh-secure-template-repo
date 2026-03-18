package log

import (
	"fmt"
	"log"
	"os"
)

// Logger defines the logging interface used throughout the application.
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// StdLogger implements Logger using the standard library log package.
// Normally: Info/Debug → STDOUT, Warn/Error → STDERR.
// In JSON mode: ALL output → STDERR so STDOUT is reserved for JSON data.
type StdLogger struct {
	debug  bool
	stdout *log.Logger
	stderr *log.Logger
}

// NewLogger creates a new StdLogger with optional debug output.
// If jsonMode is true, all log output goes to STDERR.
func NewLogger(debug bool, jsonMode ...bool) *StdLogger {
	out := os.Stdout
	if len(jsonMode) > 0 && jsonMode[0] {
		out = os.Stderr
	}
	return &StdLogger{
		debug:  debug,
		stdout: log.New(out, "", log.LstdFlags),
		stderr: log.New(os.Stderr, "", log.LstdFlags),
	}
}

func (l *StdLogger) Debug(format string, args ...interface{}) {
	if l.debug {
		l.stdout.Output(2, fmt.Sprintf("[DEBUG] "+format, args...))
	}
}

func (l *StdLogger) Info(format string, args ...interface{}) {
	l.stdout.Output(2, fmt.Sprintf("[INFO] "+format, args...))
}

func (l *StdLogger) Warn(format string, args ...interface{}) {
	l.stderr.Output(2, fmt.Sprintf("[WARN] "+format, args...))
}

func (l *StdLogger) Error(format string, args ...interface{}) {
	l.stderr.Output(2, fmt.Sprintf("[ERROR] "+format, args...))
}
