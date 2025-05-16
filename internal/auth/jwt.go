package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService struct {
	accessSecret  string
	refreshSecret string
}

func NewJWTService(accessSecret string, refreshSecret string) *JWTService {
	return &JWTService{
		accessSecret:  accessSecret,
		refreshSecret: refreshSecret,
	}
}

type TokenType string

const (
	TokenTypeAccess  TokenType = "access_token"
	TokenTypeRefresh TokenType = "refresh_token"
)

func (t TokenType) String() string {
	switch t {
	case TokenTypeAccess:
		return "access_token"
	case TokenTypeRefresh:
		return "refresh_token"
	default:
		return "unknown"
	}
}

func (t TokenType) Expiry() time.Duration {
	switch t {
	case TokenTypeAccess:
		return accessTokenExpiry
	case TokenTypeRefresh:
		return refreshTokenExpiry
	default:
		return invalidTokenExpiry
	}
}

type Claims struct {
	jwt.RegisteredClaims
	Type     TokenType `json:"type"`
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
}

func (c *Claims) String() string {
	return fmt.Sprintf("%+v", *c)
}

func (j *JWTService) Issue(
	tt TokenType,
	userID uuid.UUID,
	username string,
) (string, time.Time, error) {
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiry(tt))),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Type:     tt,
		UserID:   userID,
		Username: username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := j.sign(token, tt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, now.Add(tokenExpiry(tt)), nil
}

func (j *JWTService) Validate(signedToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				return nil, errors.New("invalid token claims")
			}

			switch claims.Type {
			case TokenTypeAccess:
				return []byte(j.accessSecret), nil
			case TokenTypeRefresh:
				return []byte(j.refreshSecret), nil
			default:
				return nil, errors.New("invalid token type")
			}
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		err = validateRegisteredClaims(claims)
		if err != nil {
			return nil, err
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (j *JWTService) sign(token *jwt.Token, tt TokenType) (string, error) {
	switch tt {
	case TokenTypeAccess:
		return token.SignedString([]byte(j.accessSecret))
	case TokenTypeRefresh:
		return token.SignedString([]byte(j.refreshSecret))
	default:
		return "", errors.New("invalid token type provided")
	}
}

const (
	accessTokenExpiry  = 15 * time.Minute
	refreshTokenExpiry = 7 * 24 * time.Hour
	invalidTokenExpiry = 0 * time.Second
)

func tokenExpiry(tt TokenType) time.Duration {
	switch tt {
	case TokenTypeAccess:
		return accessTokenExpiry
	case TokenTypeRefresh:
		return refreshTokenExpiry
	default:
		return invalidTokenExpiry
	}
}

func validateRegisteredClaims(claims *Claims) error {
	now := time.Now()

	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || now.After(exp.Time) {
		return errors.New("token is expired")
	}

	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil && now.Before(nbf.Time) {
		return errors.New("token not valid yet (nbf)")
	}

	return nil
}
