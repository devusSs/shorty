// Package env provides types
// and functions to load, parse
// and validate environment variables.
package env

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// SetEnvFile sets the .env file
// to load environment variables from.
// The default value is "" and results
// in no .env file being used.
func SetEnvFile(path string) {
	file = path
}

// SetPrefix sets the prefix
// which will be prepended to
// each environment variables
// when being loaded and parsed.
func SetPrefix(p string) {
	prefix = p
}

// SetRequiredIfNoDefault sets whether
// an environment variables will be
// considered required if it does not
// have a default value on the Env struct.
func SetRequiredIfNoDefault(b bool) {
	requiredIfNoDef = b
}

// Env holds the loaded, parsed
// and validated environment variables.
type Env struct {
	PostgresDSN        string   `env:"POSTGRES_DSN,notEmpty"         json:"postgres_dsn"`
	ServerPort         uint16   `env:"SERVER_PORT"                   json:"server_port"          envDefault:"1337"`
	AccessTokenSecret  string   `env:"ACCESS_TOKEN_SECRET,notEmpty"  json:"access_token_secret"`
	RefreshTokenSecret string   `env:"REFRESH_TOKEN_SECRET,notEmpty" json:"refresh_token_secret"`
	BackendDomain      *url.URL `env:"BACKEND_DOMAIN,notEmpty"       json:"backend_domain"       envDefault:"localhost:1337"`
}

// String implements the stringer interface
// for the Env struct.
func (e *Env) String() string {
	return fmt.Sprintf("%+v", *e)
}

const (
	minAccessSecretLength  = 32
	minRefreshSecretLength = 48
)

func (e *Env) validate() error {
	u, err := url.Parse(e.PostgresDSN)
	if err != nil {
		return fmt.Errorf("failed to parse postgres dsn: %w", err)
	}

	q := u.Query()
	if !q.Has("sslmode") {
		return fmt.Errorf("missing ssl mode in postgres dsn")
	}

	accessSecret, err := base64.StdEncoding.DecodeString(e.AccessTokenSecret)
	if err != nil {
		return fmt.Errorf("failed to decode access token secret from base64: %w", err)
	}

	refreshSecret, err := base64.StdEncoding.DecodeString(e.RefreshTokenSecret)
	if err != nil {
		return fmt.Errorf("failed to decode refresh token secret from base64: %w", err)
	}

	if len(accessSecret) < minAccessSecretLength {
		return fmt.Errorf(
			"access token secret below min length: want: %d, got: %d",
			minAccessSecretLength,
			len(accessSecret),
		)
	}

	if len(refreshSecret) < minRefreshSecretLength {
		return fmt.Errorf(
			"refresh token secret below min length: want: %d, got: %d",
			minRefreshSecretLength,
			len(refreshSecret),
		)
	}

	return nil
}

func Load() (*Env, error) {
	if file != "" {
		err := loadEnvFile()
		if err != nil {
			return nil, fmt.Errorf("failed to load env file: %w", err)
		}
	}

	e, err := loadEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to load env: %w", err)
	}

	err = e.validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate env: %w", err)
	}

	return e, nil
}

func loadEnvFile() error {
	return godotenv.Load(file)
}

func loadEnv() (*Env, error) {
	e := &Env{}
	opts := env.Options{
		Prefix:          prefix,
		RequiredIfNoDef: requiredIfNoDef,
	}

	err := env.ParseWithOptions(e, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse env: %w", err)
	}

	return e, nil
}

var (
	file            = ""
	prefix          = "SHORTY_"
	requiredIfNoDef = true
)
