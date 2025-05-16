package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJWTService_IssueAndValidateAccessToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"

	tokenString, expiresAt, err := jwtService.Issue(TokenTypeAccess, userID, username)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	assert.True(t, expiresAt.After(time.Now()))

	claims, err := jwtService.Validate(tokenString)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, TokenTypeAccess, claims.Type)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)
}

func TestJWTService_IssueAndValidateRefreshToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"

	tokenString, expiresAt, err := jwtService.Issue(TokenTypeRefresh, userID, username)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	assert.True(t, expiresAt.After(time.Now()))

	claims, err := jwtService.Validate(tokenString)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, TokenTypeRefresh, claims.Type)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)
}

func TestJWTService_Validate_InvalidToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := NewJWTService(accessSecret, refreshSecret)

	_, err := jwtService.Validate("invalid-token")
	assert.Error(t, err)
}

func TestJWTService_Validate_ExpiredToken(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := NewJWTService(accessSecret, refreshSecret)

	expiredClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		Type:     TokenTypeAccess,
		UserID:   uuid.New(),
		Username: "testuser",
	}

	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString([]byte(accessSecret))
	assert.NoError(t, err)

	_, err = jwtService.Validate(expiredTokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestJWTService_Validate_WrongSecret(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"
	tokenString, _, err := jwtService.Issue(TokenTypeAccess, userID, username)
	assert.NoError(t, err)

	wrongSecretJWTService := NewJWTService("wrong-secret", refreshSecret)
	_, err = wrongSecretJWTService.Validate(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestJWTService_Validate_InvalidTokenType(t *testing.T) {
	accessSecret := "access-test-secret"
	refreshSecret := "refresh-test-secret"
	jwtService := NewJWTService(accessSecret, refreshSecret)

	userID := uuid.New()
	username := "testuser"

	claims := Claims{
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
	assert.NoError(t, err)

	_, err = jwtService.Validate(signedToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestValidateRegisteredClaims_Valid(t *testing.T) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	err := validateRegisteredClaims(&claims)
	assert.NoError(t, err)
}

func TestValidateRegisteredClaims_Expired(t *testing.T) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	err := validateRegisteredClaims(&claims)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestValidateRegisteredClaims_NotValidYet(t *testing.T) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	err := validateRegisteredClaims(&claims)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token not valid yet")
}
