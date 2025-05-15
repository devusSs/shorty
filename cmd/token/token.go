package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"

	"github.com/devusSs/shorty/pkg/database"
	"github.com/devusSs/shorty/pkg/env"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	username := flag.String("username", "", "username to generate the token for")
	flag.Parse()

	if *username == "" {
		logError("username cannot be empty")
		os.Exit(1)
	}

	os.Exit(run(*username))
}

func run(username string) int {
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	dbConn, err := pgxpool.New(ctx, env.PostgresDSN)
	if err != nil {
		logError("failed to establish db connection", slog.Any("err", err))
		return 1
	}
	defer dbConn.Close()

	logDebug("connected to database", slog.String("dsn", env.PostgresDSN))

	db := database.New(dbConn)
	token, err := db.CreateToken(ctx, username)
	if err != nil {
		logError("failed to create token", slog.Any("err", err))
		return 1
	}

	logInfo("created token", slog.Any("token", token))

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

func logInfo(msg string, args ...any) {
	slog.With(slog.String("prefix", "main")).Info(msg, args...)
}
