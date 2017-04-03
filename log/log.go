// Package log purposed for error handling, verbosity level, output formatting, etc.
package log

import (
	"fmt"
	"log/syslog"
	"os"

	"github.com/Sirupsen/logrus"
)

var (
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel = logrus.DebugLevel
	// InfoLevel level. General operational entries about what's going on inside the application.
	InfoLevel = logrus.InfoLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel = logrus.WarnLevel
	// ErrorLevel level. Logs. Used for errors that should definitely be noted. Commonly used for hooks to send errors to an error tracking service.
	ErrorLevel = logrus.ErrorLevel
	// FatalLevel level. Logs and then calls `os.Exit(1)`. It will exit even if the logging level is set to Panic.
	FatalLevel = logrus.FatalLevel
	// PanicLevel level, highest level of severity.
	PanicLevel = logrus.PanicLevel
)

var (
	syslogServer string
	appName      string
)

func init() {
	format := new(logrus.TextFormatter)
	format.FullTimestamp = true
	format.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(format)
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)
}

// Check provides ability to check error state, write debug information
// and perform action by error level
func Check(level logrus.Level, msg string, err error) bool {
	if err != nil {
		switch level {
		case logrus.PanicLevel:
			Panic(msg, ", ", err)
		case logrus.FatalLevel:
			Fatal(msg, ", ", err)
		case logrus.ErrorLevel:
			Error(msg, ", ", err)
		case logrus.WarnLevel:
			Warn(msg, ", ", err)
		case logrus.InfoLevel:
			Info(msg, ", ", err)
		case logrus.DebugLevel:
			Debug(msg, ", ", err)
		}
		return true
	}
	logrus.Debug(msg)
	return false
}

// Level sets output level
func Level(level logrus.Level) {
	logrus.SetLevel(level)
}

// Panic stops process after showing panic message. Highest error level
func Panic(msg ...interface{}) {
	logrus.SetOutput(os.Stderr)
	logrus.Panic(msg...)
	sendSyslog(syslog.LOG_EMERG, msg...)
}

// Fatal stops process after showing fatal message.
func Fatal(msg ...interface{}) {
	logrus.SetOutput(os.Stderr)
	logrus.Fatal(msg...)
	sendSyslog(syslog.LOG_CRIT, msg...)
}

// Error stops process after showing error message.
func Error(msg ...interface{}) {
	logrus.SetOutput(os.Stderr)
	logrus.Error(msg...)
	sendSyslog(syslog.LOG_ERR, msg...)
	os.Exit(1)
}

// Warn keeps process working after showing warning message.
func Warn(msg ...interface{}) {
	logrus.Warn(msg...)
	sendSyslog(syslog.LOG_WARNING, msg...)
}

// Info keeps process working after showing information message.
func Info(msg ...interface{}) {
	logrus.Info(msg...)
	sendSyslog(syslog.LOG_INFO, msg...)
}

// Debug logs debug information
func Debug(msg ...interface{}) {
	logrus.Debug(msg...)
	sendSyslog(syslog.LOG_DEBUG, msg...)
}

func sendSyslog(level syslog.Priority, msg ...interface{}) {
	if l3, err := syslog.Dial("udp", syslogServer, level, appName); err == nil {
		l3.Write([]byte(fmt.Sprint(msg...)))
		l3.Close()
	}
}

// ActivateSyslog configures logging to send data to the syslog server
func ActivateSyslog(socket, app string) {
	syslogServer = socket
	appName = app
}
