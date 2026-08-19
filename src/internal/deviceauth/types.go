package deviceauth

import (
	"errors"
	"time"

	"github.com/soulteary/stargate/src/internal/token"
)

var (
	ErrNotFound          = errors.New("device authorization not found")
	ErrInvalidClient     = errors.New("invalid client")
	ErrInvalidScope      = errors.New("invalid scope")
	ErrExpired           = errors.New("device authorization expired")
	ErrAlreadyResolved   = errors.New("device authorization already resolved")
	ErrAuthorizationWait = errors.New("authorization pending")
	ErrSlowDown          = errors.New("slow down")
	ErrAccessDenied      = errors.New("access denied")
	ErrAlreadyConsumed   = errors.New("device authorization already consumed")
	ErrInvalidRefresh    = errors.New("invalid refresh token")
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusConsumed = "consumed"
)

type Grant struct {
	DeviceCodeHash string                  `json:"device_code_hash"`
	UserCode       string                  `json:"user_code"`
	ClientID       string                  `json:"client_id"`
	TokenRequest   token.IssueTokenRequest `json:"token_request"`
	Subject        *token.SessionSubject   `json:"subject,omitempty"`
	Status         string                  `json:"status"`
	CreatedAt      time.Time               `json:"created_at"`
	ExpiresAt      time.Time               `json:"expires_at"`
	NextPollAt     time.Time               `json:"next_poll_at"`
	PollInterval   int                     `json:"poll_interval"`
}

type RefreshGrant struct {
	ClientID     string                  `json:"client_id"`
	TokenRequest token.IssueTokenRequest `json:"token_request"`
	Subject      token.SessionSubject    `json:"subject"`
	ExpiresAt    time.Time               `json:"expires_at"`
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}
