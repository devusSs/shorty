package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/devusSs/shorty/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTService_IssueAndValidateAccessToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := auth.NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"

	tokenString, expiresAt, err := jwtService.Issue(auth.TokenTypeAccess, userID, username)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	assert.True(t, expiresAt.After(time.Now()))

	claims, err := jwtService.Validate(tokenString)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, auth.TokenTypeAccess, claims.Type)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)
}

func TestJWTService_IssueAndValidateRefreshToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := auth.NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"

	tokenString, expiresAt, err := jwtService.Issue(auth.TokenTypeRefresh, userID, username)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	assert.True(t, expiresAt.After(time.Now()))

	claims, err := jwtService.Validate(tokenString)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, auth.TokenTypeRefresh, claims.Type)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)
}

func TestJWTService_Validate_InvalidToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := auth.NewJWTService(accessSecret, refreshSecret)

	_, err := jwtService.Validate("invalid-token")
	require.Error(t, err)
}

func TestJWTService_Validate_ExpiredToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := auth.NewJWTService(accessSecret, refreshSecret)

	expiredClaims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		Type:     auth.TokenTypeAccess,
		UserID:   uuid.New(),
		Username: "testuser",
	}

	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString([]byte(accessSecret))
	require.NoError(t, err)

	_, err = jwtService.Validate(expiredTokenString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestJWTService_Validate_WrongSecret(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := auth.NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"
	tokenString, _, err := jwtService.Issue(auth.TokenTypeAccess, userID, username)
	require.NoError(t, err)

	wrongSecretJWTService := auth.NewJWTService("wrong-secret", refreshSecret)
	_, err = wrongSecretJWTService.Validate(tokenString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestJWTService_Validate_InvalidTokenType(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := auth.NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"

	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Type:     "invalid_token_type",
		UserID:   userID,
		Username: username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(accessSecret))
	require.NoError(t, err)

	_, err = jwtService.Validate(signedToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestValidateRegisteredClaims_Valid(t *testing.T) {
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	err := validateRegisteredClaims(&claims)
	require.NoError(t, err)
}

func TestValidateRegisteredClaims_Expired(t *testing.T) {
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	err := validateRegisteredClaims(&claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestValidateRegisteredClaims_NotValidYet(t *testing.T) {
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	err := validateRegisteredClaims(&claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not valid yet")
}

func validateRegisteredClaims(claims *auth.Claims) error {
	now := time.Now()

	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || now.After(exp.Time) {
		return errors.New("token is expired")
	}

	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil && now.Before(nbf.Time) {
		return errors.New("token not valid yet (nbf)")
	}

	return nil
}
