package gormzerologger

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type GormZerologger struct {
	Logger                    zerolog.Logger
	LogLevel                  logger.LogLevel
	SlowThreshold             time.Duration
	IgnoreRecordNotFoundError bool
}

func New(logLevel string) *GormZerologger {
	return &GormZerologger{
		Logger:                    log.Logger, // Utilise le logger global
		LogLevel:                  parseGormLogLevel(logLevel),
		SlowThreshold:             200 * time.Millisecond,
		IgnoreRecordNotFoundError: true,
	}
}

func parseGormLogLevel(level string) logger.LogLevel {
	switch level {
	case "debug", "trace":
		return logger.Info // Log toutes les requêtes
	case "info":
		return logger.Info // Log toutes les requêtes
	case "warn":
		return logger.Warn // Log seulement les requêtes lentes
	case "error":
		return logger.Error // Log seulement les erreurs
	default:
		return logger.Info
	}
}

func (l *GormZerologger) LogMode(level logger.LogLevel) logger.Interface {
	newLogger := *l
	newLogger.LogLevel = level
	return &newLogger
}

func (l *GormZerologger) Info(ctx context.Context, msg string, data ...interface{}) {
	if l.LogLevel >= logger.Info {
		l.Logger.Info().Msgf(msg, data...)
	}
}

func (l *GormZerologger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if l.LogLevel >= logger.Warn {
		l.Logger.Warn().Msgf(msg, data...)
	}
}

func (l *GormZerologger) Error(ctx context.Context, msg string, data ...interface{}) {
	if l.LogLevel >= logger.Error {
		l.Logger.Error().Msgf(msg, data...)
	}
}

func (l *GormZerologger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.LogLevel <= logger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	logEvent := l.Logger.With().
		Dur("elapsed_ms", elapsed).
		Int64("rows", rows).
		Str("sql", sql).
		Logger()

	switch {
	case err != nil && l.LogLevel >= logger.Error && (!errors.Is(err, gorm.ErrRecordNotFound) || !l.IgnoreRecordNotFoundError):
		logEvent.Error().
			Err(err).
			Msg("database query error")

	case elapsed > l.SlowThreshold && l.SlowThreshold != 0 && l.LogLevel >= logger.Warn:
		logEvent.Warn().
			Dur("threshold", l.SlowThreshold).
			Msg("slow database query")

	case l.LogLevel >= logger.Info:
		logEvent.Info().
			Msg("database query")
	}
}
