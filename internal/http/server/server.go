package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/devusSs/shorty/internal/http/handlers"
	"github.com/devusSs/shorty/pkg/database"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	db     *database.Queries
	port   uint16
	server *http.Server
}

func NewServer(db *database.Queries, port uint16) *Server {
	return &Server{
		db:     db,
		port:   port,
		server: nil,
	}
}

func (s *Server) RegisterHandlers(accessSecret string, refreshSecret string) {
	router := s.setup()

	userHandler := handlers.NewUserHandler(s.db, accessSecret, refreshSecret)

	router.Route("/api/v1", func(api chi.Router) {
		api.Route("/users", func(users chi.Router) {
			users.Post("/register", userHandler.Register)
			users.Post("/login", userHandler.Login)
		})
	})
}

// Start starts the server and blocks until the ctx
// is canceled or an error occurs.
func (s *Server) Start(ctx context.Context) error {
	if s.server == nil {
		return errors.New("run RegisterHandlers first")
	}

	errC := make(chan error, 1)
	go func(errC chan error) {
		defer close(errC)

		logInfo("Start", slog.String("action", "listen and serve"), slog.Int("port", int(s.port)))

		err := s.server.ListenAndServe()
		if err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				errC <- err
				return
			}

			return
		}
	}(errC)

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()

		err := s.server.Shutdown(shutdownCtx)
		if err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}

		logInfo("Start", slog.String("action", "shutdown"), slog.String("result", "success"))
	case err := <-errC:
		return fmt.Errorf("failed to listen and server: %w", err)
	}

	return nil
}

const shutdownTimeout = 10 * time.Second

const defaultReadHeaderTimeout = 5 * time.Second

func (s *Server) setup() *chi.Mux {
	r := chi.NewRouter()

	s.server = &http.Server{
		Addr:              ":" + strconv.Itoa(int(s.port)),
		Handler:           r,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}

	return r
}

func logInfo(msg string, args ...any) {
	slog.With(slog.String("prefix", "server")).Info(msg, args...)
}
