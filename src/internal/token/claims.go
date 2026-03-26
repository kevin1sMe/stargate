package token

import "github.com/golang-jwt/jwt/v5"

type SessionSubject struct {
	UserID string
	Phone  string
	Email  string
	Role   string
	Name   string
	AMR    []string
	Scopes []string
}

type IssueTokenRequest struct {
	Audience   string         `json:"audience"`
	Scope      []string       `json:"scope"`
	TTLSeconds int            `json:"ttl_seconds"`
	Resource   map[string]any `json:"resource"`
}

type Claims struct {
	Scope    []string       `json:"scope,omitempty"`
	Role     string         `json:"role,omitempty"`
	AMR      []string       `json:"amr,omitempty"`
	Email    string         `json:"email,omitempty"`
	Phone    string         `json:"phone,omitempty"`
	Name     string         `json:"name,omitempty"`
	Resource map[string]any `json:"resource,omitempty"`
	jwt.RegisteredClaims
}

type TokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  int64  `json:"issued_at"`
}
