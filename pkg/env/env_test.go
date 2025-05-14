package env_test

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devusSs/shorty/pkg/env"
)

func generateBase64Secret(length int) string {
	secret := make([]byte, length)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(secret)
}

func setValidEnvVars() {
	_ = os.Setenv(
		"SHORTY_POSTGRES_DSN",
		"postgres://user:pass@localhost:5432/dbname?sslmode=disable",
	)
	_ = os.Setenv("SHORTY_SERVER_PORT", "8080")
	_ = os.Setenv("SHORTY_ACCESS_TOKEN_SECRET", generateBase64Secret(32))
	_ = os.Setenv("SHORTY_REFRESH_TOKEN_SECRET", generateBase64Secret(32))
	_ = os.Setenv("SHORTY_BACKEND_DOMAIN", "http://localhost:8080")
}

func clearEnvVars() {
	_ = os.Unsetenv("SHORTY_POSTGRES_DSN")
	_ = os.Unsetenv("SHORTY_SERVER_PORT")
	_ = os.Unsetenv("SHORTY_ACCESS_TOKEN_SECRET")
	_ = os.Unsetenv("SHORTY_REFRESH_TOKEN_SECRET")
	_ = os.Unsetenv("SHORTY_BACKEND_DOMAIN")
}

func TestLoad_ValidEnv(t *testing.T) {
	clearEnvVars()
	setValidEnvVars()

	cfg, err := env.Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "postgres://user:pass@localhost:5432/dbname?sslmode=disable", cfg.PostgresDSN)
	assert.Equal(t, uint16(8080), cfg.ServerPort)
	assert.NotEmpty(t, cfg.AccessTokenSecret)
	assert.NotEmpty(t, cfg.RefreshTokenSecret)
	assert.Equal(t, "http://localhost:8080", cfg.BackendDomain.String())
}

func TestLoad_InvalidDSN(t *testing.T) {
	clearEnvVars()
	setValidEnvVars()
	_ = os.Setenv("SHORTY_POSTGRES_DSN", "not-a-valid-dsn")

	_, err := env.Load()
	require.Error(t, err)

	assert.Contains(t, err.Error(), "missing ssl mode in postgres dsn")
}

func TestLoad_MissingSSLMode(t *testing.T) {
	clearEnvVars()
	setValidEnvVars()
	_ = os.Setenv("SHORTY_POSTGRES_DSN", "postgres://user:pass@localhost:5432/dbname")

	_, err := env.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing ssl mode")
}

func TestLoad_InvalidAccessTokenBase64(t *testing.T) {
	clearEnvVars()
	setValidEnvVars()
	_ = os.Setenv("SHORTY_ACCESS_TOKEN_SECRET", "not-base64!")

	_, err := env.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode access token")
}

func TestLoad_InvalidRefreshTokenBase64(t *testing.T) {
	clearEnvVars()
	setValidEnvVars()
	_ = os.Setenv("SHORTY_REFRESH_TOKEN_SECRET", "also-not-base64")

	_, err := env.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode refresh token")
}

func TestLoad_TooShortSecrets(t *testing.T) {
	clearEnvVars()
	setValidEnvVars()

	_ = os.Setenv("SHORTY_ACCESS_TOKEN_SECRET", generateBase64Secret(16))
	_ = os.Setenv("SHORTY_REFRESH_TOKEN_SECRET", generateBase64Secret(16))

	_, err := env.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access token secret below min length")
}

func TestSetPrefix_AffectsLoading(t *testing.T) {
	clearEnvVars()
	_ = os.Setenv(
		"CUSTOM_POSTGRES_DSN",
		"postgres://user:pass@localhost:5432/dbname?sslmode=disable",
	)
	_ = os.Setenv("CUSTOM_ACCESS_TOKEN_SECRET", generateBase64Secret(32))
	_ = os.Setenv("CUSTOM_REFRESH_TOKEN_SECRET", generateBase64Secret(32))
	_ = os.Setenv("CUSTOM_BACKEND_DOMAIN", "http://custom:1234")

	env.SetPrefix("CUSTOM_")

	cfg, err := env.Load()
	require.NoError(t, err)
	assert.Equal(t, "http://custom:1234", cfg.BackendDomain.String())
}
