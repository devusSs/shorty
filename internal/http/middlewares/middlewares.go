package middlewares

import (
	"log/slog"
	"net/http"
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
