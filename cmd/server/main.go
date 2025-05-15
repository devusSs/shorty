package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/devusSs/shorty/internal/http/server"
	"github.com/devusSs/shorty/pkg/database"
	"github.com/devusSs/shorty/pkg/env"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	os.Exit(run())
}

func run() int {
	if isDev() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		env.SetEnvFile(".env")
		env.SetPrefix("DEV_SHORTY_")
		logWarn("debug mode enabled, might leak sensitive data")
	}

	env, err := env.Load()
	if err != nil {
		logError("failed to load env", slog.Any("err", err))
		return 1
	}

	logDebug("loaded env", slog.Any("env", env))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dbConn, err := pgxpool.New(ctx, env.PostgresDSN)
	if err != nil {
		logError("failed to establish db connection", slog.Any("err", err))
		return 1
	}
	defer dbConn.Close()

	logDebug("connected to database", slog.String("dsn", env.PostgresDSN))

	srv := server.NewServer(database.New(dbConn), env.ServerPort)
	srv.RegisterHandlers()
	err = srv.Start(ctx)
	if err != nil {
		logError("failed to start server", slog.Any("err", err))
		return 1
	}

	return 0
}

func isDev() bool {
	dev := os.Getenv("SHORTY_DEVELOPMENT")
	b, err := strconv.ParseBool(dev)
	return err == nil && b
}

func logWarn(msg string, args ...any) {
	slog.With(slog.String("prefix", "main")).Warn(msg, args...)
}

func logError(msg string, args ...any) {
	slog.With(slog.String("prefix", "main")).Error(msg, args...)
}

func logDebug(msg string, args ...any) {
	slog.With(slog.String("prefix", "main")).Debug(msg, args...)
}
