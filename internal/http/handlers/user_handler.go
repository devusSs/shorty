package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/devusSs/shorty/internal/hashing"
	"github.com/devusSs/shorty/internal/http/handlers/validators"
	"github.com/devusSs/shorty/pkg/database"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type UserHandler struct {
	db        *database.Queries
	validator *validator.Validate
}

func NewUserHandler(db *database.Queries) *UserHandler {
	v := validator.New()
	validators.RegisterPasswordValidator(v)

	return &UserHandler{
		db:        db,
		validator: v,
	}
}

func (u *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	type registerUserRequest struct {
		Username      string `json:"username"       validate:"required,min=6,max=16"`
		Password      string `json:"password"       validate:"required,min=8,max=64,password"`
		RegisterToken string `json:"register_token" validate:"required"`
	}

	model := &registerUserRequest{}
	err := json.NewDecoder(r.Body).Decode(model)
	if err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body provided")
		return
	}

	err = u.validator.Struct(model)
	if err != nil {
		// TODO: tell the user the actual error -> only shows tag
		sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	uuid, err := uuid.Parse(model.RegisterToken)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid register token provided")
		return
	}

	tokenID := pgtype.UUID{Bytes: uuid, Valid: true}

	token, err := u.db.GetTokenByID(r.Context(), tokenID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sendError(w, http.StatusNotFound, "token does not exist")
			return
		}

		u.logError("Register", slog.String("action", "get_token_by_id"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if token.Username != model.Username {
		sendError(w, http.StatusUnauthorized, "token username does not match provided username")
		return
	}

	if token.Used {
		sendError(w, http.StatusConflict, "token already used")
		return
	}

	err = u.db.SetTokenUsed(r.Context(), token.ID)
	if err != nil {
		u.logError("Register", slog.String("action", "set_token_used"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	u.logInfo(
		"Register",
		slog.String("action", "token_used"),
		slog.String("token", token.ID.String()),
		slog.String("username", model.Username),
	)

	hashedPassword, err := hashing.HashPassword(model.Password)
	if err != nil {
		u.logError("Register", slog.String("action", "hash_password"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	user, err := u.db.CreateUser(r.Context(), database.CreateUserParams{
		Username: model.Username,
		Password: hashedPassword,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				sendError(w, http.StatusConflict, "username already exists")
				return
			}
		}

		u.logError("Register", slog.String("action", "create_user"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	type registerUserResponse struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		Note     string `json:"note"`
	}

	resp := &registerUserResponse{
		UserID:   user.ID.String(),
		Username: user.Username,
		Note:     "Please login to generate your tokens.",
	}

	u.logInfo(
		"Register",
		slog.String("action", "user_registered"),
		slog.String("user_id", resp.UserID),
		slog.String("username", resp.Username),
	)
	sendJSON(w, http.StatusCreated, resp)
}

func (u *UserHandler) logError(msg string, args ...any) {
	slog.With(slog.String("prefix", "user_handler")).Error(msg, args...)
}

func (u *UserHandler) logInfo(msg string, args ...any) {
	slog.With(slog.String("prefix", "user_handler")).Info(msg, args...)
}
