package validators

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

func RegisterPasswordValidator(v *validator.Validate) {
	_ = v.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()
		var (
			upper   = regexp.MustCompile(`[A-Z]`)
			lower   = regexp.MustCompile(`[a-z]`)
			digit   = regexp.MustCompile(`[0-9]`)
			special = regexp.MustCompile(`[^a-zA-Z0-9]`)
		)
		return upper.MatchString(password) &&
			lower.MatchString(password) &&
			digit.MatchString(password) &&
			special.MatchString(password)
	})
}
