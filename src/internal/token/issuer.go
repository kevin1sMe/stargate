package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenNotConfigured    = errors.New("token issuer is not configured")
	ErrInvalidAudience       = errors.New("audience is not allowed")
	ErrInvalidTTL            = errors.New("ttl_seconds must be positive")
	ErrScopeNotAllowed       = errors.New("requested scope exceeds session scope")
	ErrTOTPRequired          = errors.New("audience requires totp authentication")
	ErrSessionMissingSubject = errors.New("session user_id is required")
)

type Issuer struct {
	settings   Settings
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

func NewIssuerFromConfig() (*Issuer, error) {
	return NewIssuer(SettingsFromConfig())
}

func NewIssuer(settings Settings) (*Issuer, error) {
	if settings.SigningKey == "" || settings.Issuer == "" || len(settings.AllowedAudiences) == 0 {
		return nil, ErrTokenNotConfigured
	}

	privateKey, err := parsePrivateKey(settings.SigningKey)
	if err != nil {
		return nil, err
	}

	keyID := settings.KeyID
	if keyID == "" {
		keyID = "stargate-ed25519"
	}

	settings.KeyID = keyID

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("failed to derive ed25519 public key")
	}

	return &Issuer{
		settings:   settings,
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (i *Issuer) Issue(subject SessionSubject, req IssueTokenRequest) (*TokenResponse, error) {
	if subject.UserID == "" {
		return nil, ErrSessionMissingSubject
	}

	audience := strings.TrimSpace(req.Audience)
	if audience == "" {
		return nil, ErrInvalidAudience
	}
	if _, ok := i.settings.AllowedAudiences[audience]; !ok {
		return nil, ErrInvalidAudience
	}
	if _, needsTOTP := i.settings.TOTPRequiredAudiences[audience]; needsTOTP && !containsString(subject.AMR, "totp") {
		return nil, ErrTOTPRequired
	}

	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = i.settings.DefaultTTLSeconds
	}
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	if ttl > i.settings.MaxTTLSeconds {
		ttl = i.settings.MaxTTLSeconds
	}

	scopes := req.Scope
	if len(scopes) == 0 {
		scopes = append([]string(nil), subject.Scopes...)
	}
	if !isSubset(scopes, subject.Scopes) {
		return nil, ErrScopeNotAllowed
	}

	now := time.Now().UTC()
	claims := Claims{
		Scope:    scopes,
		Role:     subject.Role,
		AMR:      append([]string(nil), subject.AMR...),
		Email:    subject.Email,
		Phone:    subject.Phone,
		Name:     subject.Name,
		Resource: req.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.settings.Issuer,
			Subject:   subject.UserID,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
			ID:        newTokenID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = i.settings.KeyID

	signed, err := token.SignedString(i.privateKey)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		Token:     signed,
		TokenType: "Bearer",
		ExpiresIn: ttl,
		IssuedAt:  now.Unix(),
	}, nil
}

func (i *Issuer) JWKS() JWKS {
	return JWKS{
		Keys: []JWK{{
			Kty: "OKP",
			Crv: "Ed25519",
			Alg: "EdDSA",
			Use: "sig",
			Kid: i.settings.KeyID,
			X:   base64.RawURLEncoding.EncodeToString(i.publicKey),
		}},
	}
}

func (i *Issuer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), i.publicKey...)
}

func parsePrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrTokenNotConfigured
	}

	if strings.HasPrefix(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM token signing key")
		}

		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("token signing key must be an Ed25519 private key")
		}
		return privateKey, nil
	}

	decoded, err := decodeRawKey(raw)
	if err != nil {
		return nil, err
	}

	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("unexpected token signing key length: %d", len(decoded))
	}
}

func decodeRawKey(raw string) ([]byte, error) {
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}

	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder(raw)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

func isSubset(requested, available []string) bool {
	if len(requested) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(available))
	for _, scope := range available {
		allowed[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowed[scope]; !ok {
			return false
		}
	}
	return true
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func newTokenID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (j JWKS) JSON() ([]byte, error) {
	return json.Marshal(j)
}
