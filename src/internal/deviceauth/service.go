package deviceauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/soulteary/stargate/src/internal/config"
	"github.com/soulteary/stargate/src/internal/token"
)

const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXYZ23456789"

type Settings struct {
	Enabled         bool
	ClientID        string
	Audience        string
	AllowedScopes   map[string]struct{}
	VerificationURI string
	CodeTTL         time.Duration
	PollInterval    int
	RefreshTTL      time.Duration
}

type Service struct {
	store    Store
	settings Settings
}

func SettingsFromConfig() Settings {
	return Settings{
		Enabled:         config.DeviceAuthEnabled.ToBool(),
		ClientID:        strings.TrimSpace(config.DeviceAuthClientID.String()),
		Audience:        strings.TrimSpace(config.DeviceAuthAudience.String()),
		AllowedScopes:   csvSet(config.DeviceAuthAllowedScopes.String()),
		VerificationURI: strings.TrimSpace(config.DeviceAuthVerificationURI.String()),
		CodeTTL:         time.Duration(positiveInt(config.DeviceAuthCodeTTLSeconds.String(), 600)) * time.Second,
		PollInterval:    positiveInt(config.DeviceAuthPollIntervalSeconds.String(), 5),
		RefreshTTL:      time.Duration(positiveInt(config.DeviceAuthRefreshTTLSeconds.String(), 86400)) * time.Second,
	}
}

func NewService(store Store, settings Settings) *Service {
	return &Service{store: store, settings: settings}
}

func (s *Service) Enabled() bool      { return s.settings.Enabled }
func (s *Service) Settings() Settings { return s.settings }

func (s *Service) Start(ctx context.Context, clientID string, scopes []string, verificationURI string, now time.Time) (*DeviceAuthorizationResponse, error) {
	if !s.settings.Enabled || clientID != s.settings.ClientID || clientID == "" {
		return nil, ErrInvalidClient
	}
	if len(scopes) == 0 {
		for scope := range s.settings.AllowedScopes {
			scopes = append(scopes, scope)
		}
	}
	for _, scope := range scopes {
		if _, ok := s.settings.AllowedScopes[scope]; !ok {
			return nil, ErrInvalidScope
		}
	}
	if s.settings.Audience == "" {
		return nil, ErrInvalidClient
	}
	if s.settings.VerificationURI != "" {
		verificationURI = s.settings.VerificationURI
	}
	verificationURI = strings.TrimRight(verificationURI, "/")
	if verificationURI == "" {
		return nil, errors.New("verification URI is not configured")
	}

	for attempt := 0; attempt < 5; attempt++ {
		deviceCode, err := randomSecret(32)
		if err != nil {
			return nil, err
		}
		userCode, err := randomUserCode()
		if err != nil {
			return nil, err
		}
		grant := &Grant{
			DeviceCodeHash: HashSecret(deviceCode),
			UserCode:       userCode,
			ClientID:       clientID,
			TokenRequest: token.IssueTokenRequest{
				Audience: s.settings.Audience,
				Scope:    append([]string(nil), scopes...),
			},
			Status:       StatusPending,
			CreatedAt:    now.UTC(),
			ExpiresAt:    now.UTC().Add(s.settings.CodeTTL),
			PollInterval: s.settings.PollInterval,
		}
		if err := s.store.Create(ctx, grant); err != nil {
			continue
		}
		complete := verificationURI + "?user_code=" + url.QueryEscape(userCode)
		return &DeviceAuthorizationResponse{
			DeviceCode: deviceCode, UserCode: userCode,
			VerificationURI: verificationURI, VerificationURIComplete: complete,
			ExpiresIn: int(s.settings.CodeTTL.Seconds()), Interval: s.settings.PollInterval,
		}, nil
	}
	return nil, fmt.Errorf("failed to allocate device authorization codes")
}

func (s *Service) FindByUserCode(ctx context.Context, code string, now time.Time) (*Grant, error) {
	grant, err := s.store.FindByUserCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if !now.Before(grant.ExpiresAt) {
		return nil, ErrExpired
	}
	return grant, nil
}

func (s *Service) Resolve(ctx context.Context, code string, subject *token.SessionSubject, approved bool, now time.Time) (*Grant, error) {
	if approved {
		grant, err := s.FindByUserCode(ctx, code, now)
		if err != nil {
			return nil, err
		}
		if subject == nil || strings.TrimSpace(subject.UserID) == "" {
			return nil, token.ErrSessionMissingSubject
		}
		available := make(map[string]struct{}, len(subject.Scopes))
		for _, scope := range subject.Scopes {
			available[scope] = struct{}{}
		}
		for _, scope := range grant.TokenRequest.Scope {
			if _, ok := available[scope]; !ok {
				return nil, token.ErrScopeNotAllowed
			}
		}
	}
	return s.store.Resolve(ctx, code, subject, approved, now)
}

func (s *Service) ExchangeDevice(ctx context.Context, clientID, deviceCode string, now time.Time) (*OAuthTokenResponse, error) {
	if !s.settings.Enabled || clientID != s.settings.ClientID {
		return nil, ErrInvalidClient
	}
	issuer, err := token.NewIssuerFromConfig()
	if err != nil {
		return nil, err
	}
	grant, err := s.store.Poll(ctx, deviceCode, clientID, now)
	if err != nil {
		return nil, err
	}
	if grant.Subject == nil {
		return nil, ErrAuthorizationWait
	}
	access, err := issuer.Issue(*grant.Subject, grant.TokenRequest)
	if err != nil {
		return nil, err
	}
	refresh, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	refreshGrant := &RefreshGrant{
		ClientID: clientID, TokenRequest: grant.TokenRequest, Subject: *grant.Subject,
		ExpiresAt: now.UTC().Add(s.settings.RefreshTTL),
	}
	if err := s.store.CreateRefresh(ctx, refresh, refreshGrant); err != nil {
		return nil, err
	}
	return oauthResponse(access, refresh, grant.TokenRequest.Scope), nil
}

func (s *Service) ExchangeRefresh(ctx context.Context, clientID, refreshToken string, now time.Time) (*OAuthTokenResponse, error) {
	if !s.settings.Enabled || clientID != s.settings.ClientID {
		return nil, ErrInvalidClient
	}
	issuer, err := token.NewIssuerFromConfig()
	if err != nil {
		return nil, err
	}
	newRefresh, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	grant, err := s.store.RotateRefresh(ctx, refreshToken, newRefresh, clientID, now)
	if err != nil {
		return nil, err
	}
	access, err := issuer.Issue(grant.Subject, grant.TokenRequest)
	if err != nil {
		return nil, err
	}
	return oauthResponse(access, newRefresh, grant.TokenRequest.Scope), nil
}

func oauthResponse(access *token.TokenResponse, refresh string, scopes []string) *OAuthTokenResponse {
	return &OAuthTokenResponse{AccessToken: access.Token, RefreshToken: refresh, TokenType: access.TokenType, ExpiresIn: access.ExpiresIn, Scope: strings.Join(scopes, " ")}
}

func randomSecret(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomUserCode() (string, error) {
	buf := make([]byte, 8)
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = userCodeAlphabet[int(random[i])%len(userCodeAlphabet)]
	}
	return string(buf[:4]) + "-" + string(buf[4:]), nil
}

func csvSet(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if item != "" {
			out[item] = struct{}{}
		}
	}
	return out
}

func positiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
