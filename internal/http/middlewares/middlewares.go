package middlewares

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func Logging() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			slog.With("prefix", "middlewares").Info("HTTP",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote_ip", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("request_id", middleware.GetReqID(r.Context())),
				slog.String("queries", r.URL.RawQuery),
			)
		}

		return http.HandlerFunc(fn)
	}
}

type ContextKey string

const TokenContextKey ContextKey = "token"

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString == "" {
			sendError(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), TokenContextKey, tokenString)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const tokenSplitN = 2

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", tokenSplitN)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func sendJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		slog.With(slog.String("prefix", "send_json_middleware")).
			Error("could not encode json response", slog.Any("err", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func sendError(w http.ResponseWriter, code int, msg string) {
	sendJSON(w, code, map[string]string{"error": msg})
}
