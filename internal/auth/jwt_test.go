package auth_test

import (
	"testing"
	"time"

	"github.com/devusSs/shorty/internal/auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	accessSecret  = "supersecretaccesskey1234567890"
	refreshSecret = "supersecretrefreshkey123456789"
)

func setupJWTService() *auth.JWTService {
	return auth.NewJWTService(accessSecret, refreshSecret)
}

func TestTokenTypeString(t *testing.T) {
	assert.Equal(t, "access_token", auth.TokenTypeAccess.String())
	assert.Equal(t, "refresh_token", auth.TokenTypeRefresh.String())
	assert.Equal(t, "unknown", auth.TokenType("invalid").String())
}

func TestClaimsString(t *testing.T) {
	uid := uuid.New()
	c := &auth.Claims{
		Type:     auth.TokenTypeAccess,
		UserID:   uid,
		Username: "testuser",
	}
	out := c.String()
	assert.Contains(t, out, "testuser")
	assert.Contains(t, out, uid.String())
	assert.Contains(t, out, "access_token")
}

func TestIssueAndValidateAccessToken(t *testing.T) {
	service := setupJWTService()
	uid := uuid.New()

	token, err := service.Issue(auth.TokenTypeAccess, uid, "tester")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := service.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, uid, claims.UserID)
	assert.Equal(t, "tester", claims.Username)
	assert.Equal(t, auth.TokenTypeAccess, claims.Type)
}

func TestIssueAndValidateRefreshToken(t *testing.T) {
	service := setupJWTService()
	uid := uuid.New()

	token, err := service.Issue(auth.TokenTypeRefresh, uid, "refreshUser")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := service.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, uid, claims.UserID)
	assert.Equal(t, "refreshUser", claims.Username)
	assert.Equal(t, auth.TokenTypeRefresh, claims.Type)
}

func TestValidateFailsWithWrongSecret(t *testing.T) {
	service := auth.NewJWTService("wrongaccess", "wrongrefresh")
	uid := uuid.New()

	goodService := setupJWTService()
	token, err := goodService.Issue(auth.TokenTypeAccess, uid, "user")
	require.NoError(t, err)

	claims, err := service.Validate(token)
	assert.Nil(t, claims)
	assert.Error(t, err)
}

func TestValidateFailsWithMalformedToken(t *testing.T) {
	service := setupJWTService()

	token := "thisisnotavalid.jwt.token"
	claims, err := service.Validate(token)
	assert.Nil(t, claims)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestTokenExpiryDurations(t *testing.T) {
	assert.Equal(t, 15*time.Minute, auth.TokenTypeAccess.Expiry())
	assert.Equal(t, 7*24*time.Hour, auth.TokenTypeRefresh.Expiry())
	assert.Equal(t, time.Duration(0), auth.TokenType("invalid").Expiry())
}
