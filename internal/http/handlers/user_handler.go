package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/devusSs/shorty/internal/auth"
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
	db         *database.Queries
	validator  *validator.Validate
	jwtService *auth.JWTService
}

func NewUserHandler(db *database.Queries, accessSecret string, refreshSecret string) *UserHandler {
	v := validator.New()
	validators.RegisterPasswordValidator(v)

	return &UserHandler{
		db:         db,
		validator:  v,
		jwtService: auth.NewJWTService(accessSecret, refreshSecret),
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

	action, err := u.db.CreateUserAction(r.Context(), database.CreateUserActionParams{
		UserID: user.ID,
		Action: database.UserActionTypeUserRegister,
	})
	if err != nil {
		u.logError("Register", slog.String("action", "user_registered"), slog.Any("err", err))
	} else {
		u.logDebug("Register", slog.String("action", "user_registered"), slog.Any("data", action))
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

func (u *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	type loginUserRequest struct {
		Username string `json:"username" validate:"required,min=6,max=16"`
		Password string `json:"password" validate:"required,min=8,max=64,password"`
	}

	model := &loginUserRequest{}
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

	user, err := u.db.GetUserByUsername(r.Context(), model.Username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sendError(w, http.StatusNotFound, "username does not exist")
			return
		}

		u.logError("Login", slog.String("action", "get_user_by_username"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	err = hashing.ComparePasswordHash(model.Password, user.Password)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "password mismatch")
		return
	}

	at, atExpiry, err := u.jwtService.Issue(auth.TokenTypeAccess, user.ID.Bytes, user.Username)
	if err != nil {
		u.logError("Login", slog.String("action", "issue_access_token"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	rt, rtExpiry, err := u.jwtService.Issue(auth.TokenTypeRefresh, user.ID.Bytes, user.Username)
	if err != nil {
		u.logError("Login", slog.String("action", "issue_refresh_token"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	action, err := u.db.CreateUserAction(r.Context(), database.CreateUserActionParams{
		UserID: user.ID,
		Action: database.UserActionTypeUserLogin,
	})
	if err != nil {
		u.logError("Login", slog.String("action", "user_logged_in"), slog.Any("err", err))
	} else {
		u.logDebug("Login", slog.String("action", "user_logged_in"), slog.Any("data", action))
	}

	type userLoginResponse struct {
		AccessToken        string `json:"access_token"`
		RefreshToken       string `json:"refresh_token"`
		AccessTokenExpiry  string `json:"access_token_expiry"`
		RefreshTokenExpiry string `json:"refresh_token_expiry"`
		Note               string `json:"note"`
	}

	resp := &userLoginResponse{
		AccessToken:        at,
		RefreshToken:       rt,
		AccessTokenExpiry:  atExpiry.Format(time.RFC3339Nano),
		RefreshTokenExpiry: rtExpiry.Format(time.RFC3339Nano),
		Note:               "Never share these tokens with anyone.",
	}

	sendJSON(w, http.StatusOK, resp)
}

func (u *UserHandler) logError(msg string, args ...any) {
	slog.With(slog.String("prefix", "user_handler")).Error(msg, args...)
}

func (u *UserHandler) logInfo(msg string, args ...any) {
	slog.With(slog.String("prefix", "user_handler")).Info(msg, args...)
}

func (u *UserHandler) logDebug(msg string, args ...any) {
	slog.With(slog.String("prefix", "user_handler")).Debug(msg, args...)
}
