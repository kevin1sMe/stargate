package deviceauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/soulteary/stargate/src/internal/config"
	"github.com/soulteary/stargate/src/internal/token"
)

func TestDeviceAuthorizationAndRefresh(t *testing.T) {
	configureTokenIssuer(t)
	now := time.Now().UTC()
	service := NewService(NewMemoryStore(), Settings{
		Enabled: true, ClientID: "stargate-tunnelcli", Audience: "tunnel.example.com",
		AllowedScopes: map[string]struct{}{"forward": {}}, VerificationURI: "https://auth.example.com/device",
		CodeTTL: 10 * time.Minute, PollInterval: 5, RefreshTTL: 24 * time.Hour,
	})

	started, err := service.Start(context.Background(), "stargate-tunnelcli", []string{"forward"}, "", now)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if started.UserCode == "" || started.DeviceCode == "" {
		t.Fatal("expected device and user codes")
	}

	_, err = service.ExchangeDevice(context.Background(), "stargate-tunnelcli", started.DeviceCode, now)
	if err != ErrAuthorizationWait {
		t.Fatalf("expected authorization_pending, got %v", err)
	}
	_, err = service.ExchangeDevice(context.Background(), "stargate-tunnelcli", started.DeviceCode, now.Add(time.Second))
	if err != ErrSlowDown {
		t.Fatalf("expected slow_down, got %v", err)
	}

	_, err = service.Resolve(context.Background(), started.UserCode, &token.SessionSubject{
		UserID: "user-1", Scopes: []string{"forward"}, AMR: []string{"warden", "totp"},
	}, true, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	issued, err := service.ExchangeDevice(context.Background(), "stargate-tunnelcli", started.DeviceCode, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("device exchange: %v", err)
	}
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens")
	}

	refreshed, err := service.ExchangeRefresh(context.Background(), "stargate-tunnelcli", issued.RefreshToken, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("refresh exchange: %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == issued.RefreshToken {
		t.Fatal("expected rotated access and refresh tokens")
	}
	if _, err := service.ExchangeRefresh(context.Background(), "stargate-tunnelcli", issued.RefreshToken, now.Add(2*time.Minute)); err != ErrInvalidRefresh {
		t.Fatalf("expected old refresh token rejection, got %v", err)
	}
}

func TestDeviceAuthorizationRejectsScope(t *testing.T) {
	service := NewService(NewMemoryStore(), Settings{
		Enabled: true, ClientID: "cli", Audience: "tunnel",
		AllowedScopes: map[string]struct{}{"forward": {}}, CodeTTL: time.Minute, PollInterval: 5,
	})
	_, err := service.Start(context.Background(), "cli", []string{"admin"}, "https://auth.example.com/device", time.Now())
	if err != ErrInvalidScope {
		t.Fatalf("expected invalid scope, got %v", err)
	}
}

func configureTokenIssuer(t *testing.T) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	previousKey := config.TokenSigningKey.Value
	previousIssuer := config.TokenIssuer.Value
	previousAudiences := config.TokenAllowedAudiences.Value
	previousTOTP := config.TokenTOTPRequiredAudiences.Value
	t.Cleanup(func() {
		config.TokenSigningKey.Value = previousKey
		config.TokenIssuer.Value = previousIssuer
		config.TokenAllowedAudiences.Value = previousAudiences
		config.TokenTOTPRequiredAudiences.Value = previousTOTP
	})
	config.TokenSigningKey.Value = base64.StdEncoding.EncodeToString(privateKey.Seed())
	config.TokenIssuer.Value = "auth.example.com"
	config.TokenAllowedAudiences.Value = "tunnel.example.com"
	config.TokenTOTPRequiredAudiences.Value = "tunnel.example.com"
}
