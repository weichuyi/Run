// Package log 提供统一的日志功能，封装 logrus
package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func init() {
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceColors:     true,
	})
	logger.SetLevel(logrus.InfoLevel)
}

// SetLevel 根据字符串设置日志级别
func SetLevel(level string) {
	switch level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info", "":
		logger.SetLevel(logrus.InfoLevel)
	case "warning", "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	case "silent":
		logger.SetLevel(logrus.PanicLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
}

// SetJSON 切换为 JSON 格式输出
func SetJSON(enable bool) {
	if enable {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z07:00",
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}
}

// Debug 调试日志
func Debug(args ...any)                 { logger.Debug(args...) }
func Debugf(fmt string, args ...any)    { logger.Debugf(fmt, args...) }
func Info(args ...any)                  { logger.Info(args...) }
func Infof(fmt string, args ...any)     { logger.Infof(fmt, args...) }
func Warn(args ...any)                  { logger.Warn(args...) }
func Warnf(fmt string, args ...any)     { logger.Warnf(fmt, args...) }
func Error(args ...any)                 { logger.Error(args...) }
func Errorf(fmt string, args ...any)    { logger.Errorf(fmt, args...) }
func Fatal(args ...any)                 { logger.Fatal(args...) }
func Fatalf(fmt string, args ...any)    { logger.Fatalf(fmt, args...) }

// WithError 附带 error 字段
func WithError(err error) *logrus.Entry { return logger.WithError(err) }

// WithField 附带自定义字段
func WithField(key string, val any) *logrus.Entry { return logger.WithField(key, val) }

// WithFields 附带多个自定义字段
func WithFields(fields logrus.Fields) *logrus.Entry { return logger.WithFields(fields) }
