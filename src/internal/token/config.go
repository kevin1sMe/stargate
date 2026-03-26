package token

import (
	"strconv"
	"strings"

	"github.com/soulteary/stargate/src/internal/config"
)

const (
	defaultTokenTTLSeconds = 300
	defaultTokenMaxTTL     = 900
)

type Settings struct {
	SigningKey            string
	KeyID                 string
	Issuer                string
	MaxTTLSeconds         int
	DefaultTTLSeconds     int
	AllowedAudiences      map[string]struct{}
	TOTPRequiredAudiences map[string]struct{}
}

func SettingsFromConfig() Settings {
	issuer := strings.TrimSpace(config.TokenIssuer.String())
	if issuer == "" {
		issuer = strings.TrimSpace(config.AuthHost.String())
	}

	maxTTL := parsePositiveInt(config.TokenMaxTTLSeconds.String(), defaultTokenMaxTTL)
	defaultTTL := parsePositiveInt(config.TokenDefaultTTLSeconds.String(), defaultTokenTTLSeconds)
	if defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}

	return Settings{
		SigningKey:            strings.TrimSpace(config.TokenSigningKey.String()),
		KeyID:                 strings.TrimSpace(config.TokenSigningKID.String()),
		Issuer:                issuer,
		MaxTTLSeconds:         maxTTL,
		DefaultTTLSeconds:     defaultTTL,
		AllowedAudiences:      parseCSVSet(config.TokenAllowedAudiences.String()),
		TOTPRequiredAudiences: parseCSVSet(config.TokenTOTPRequiredAudiences.String()),
	}
}

func parsePositiveInt(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func parseCSVSet(value string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result[part] = struct{}{}
	}
	return result
}
