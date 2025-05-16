package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/devusSs/shorty/internal/auth"
	"github.com/devusSs/shorty/internal/http/middlewares"
	"github.com/devusSs/shorty/pkg/database"
	"github.com/jackc/pgx/v5/pgtype"
)

type TokenHandler struct {
	db         *database.Queries
	jwtService *auth.JWTService
}

func NewTokenHandler(
	db *database.Queries,
	accessSecret string,
	refreshSecret string,
) *TokenHandler {
	return &TokenHandler{db: db, jwtService: auth.NewJWTService(accessSecret, refreshSecret)}
}

func (t *TokenHandler) Validate(w http.ResponseWriter, r *http.Request) {
	// this cannot be nil since the auth middleware checks that
	// and the type cast should also work, else it must be an internal error
	authToken, ok := r.Context().Value(middlewares.TokenContextKey).(string)
	if !ok {
		t.logError("Validate", slog.String("action", "type_cast_auth_token"))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	claims, err := t.jwtService.Validate(authToken)
	if err != nil {
		sendError(w, http.StatusUnauthorized, err.Error())
		return
	}

	action, err := t.db.CreateUserAction(r.Context(), database.CreateUserActionParams{
		UserID: pgtype.UUID{Bytes: claims.UserID, Valid: true},
		Action: database.UserActionTypeTokenValidated,
	})
	if err != nil {
		t.logError("Validate", slog.String("action", "token_validated"), slog.Any("err", err))
	} else {
		t.logDebug("Validate", slog.String("action", "token_validated"), slog.Any("data", action))
	}

	type tokenResponse struct {
		Type   string `json:"type"`
		Expiry string `json:"expiry"`
		// WARN: Is this a security risk?
		UserID string `json:"user_id"`
	}

	resp := &tokenResponse{
		Type:   claims.Type.String(),
		Expiry: claims.ExpiresAt.Format(time.RFC3339Nano),
		UserID: claims.UserID.String(),
	}

	sendJSON(w, http.StatusOK, resp)
}

func (t *TokenHandler) Renew(w http.ResponseWriter, r *http.Request) {
	type renewRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	model := &renewRequest{}
	err := json.NewDecoder(r.Body).Decode(model)
	if err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body provided")
		return
	}

	if model.RefreshToken == "" {
		sendError(w, http.StatusUnauthorized, "missing refresh token in json body")
		return
	}

	claims, err := t.jwtService.Validate(model.RefreshToken)
	if err != nil {
		sendError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if claims.Type != auth.TokenTypeRefresh {
		sendError(w, http.StatusUnauthorized, "token must be a valid refresh token")
		return
	}

	at, atExpiry, err := t.jwtService.Issue(auth.TokenTypeAccess, claims.UserID, claims.Username)
	if err != nil {
		t.logError("Renew", slog.String("action", "issue_token"), slog.Any("err", err))
		sendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	action, err := t.db.CreateUserAction(r.Context(), database.CreateUserActionParams{
		UserID: pgtype.UUID{Bytes: claims.UserID, Valid: true},
		Action: database.UserActionTypeTokenRenewed,
	})
	if err != nil {
		t.logError("Renew", slog.String("action", "token_renewed"), slog.Any("err", err))
	} else {
		t.logDebug("Renew", slog.String("action", "token_renewed"), slog.Any("data", action))
	}

	type renewResponse struct {
		UserID             string `json:"user_id"`
		RefreshTokenExpiry string `json:"refresh_token_expiry"`
		AccessToken        string `json:"access_token"`
		AccessTokenExpiry  string `json:"access_token_expiry"`
	}

	resp := &renewResponse{
		UserID:             claims.UserID.String(),
		RefreshTokenExpiry: claims.ExpiresAt.Format(time.RFC3339Nano),
		AccessToken:        at,
		AccessTokenExpiry:  atExpiry.Format(time.RFC3339Nano),
	}

	sendJSON(w, http.StatusOK, resp)
}

func (t *TokenHandler) logError(msg string, args ...any) {
	slog.With(slog.String("prefix", "token_handler")).Error(msg, args...)
}

func (t *TokenHandler) logDebug(msg string, args ...any) {
	slog.With(slog.String("prefix", "token_handler")).Debug(msg, args...)
}
