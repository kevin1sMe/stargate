package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MarvinJWendt/testza"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/golang-jwt/jwt/v5"
	"github.com/soulteary/stargate/src/internal/auth"
	"github.com/soulteary/stargate/src/internal/config"
	internal_token "github.com/soulteary/stargate/src/internal/token"
)

func setupTokenConfig(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_HOST", "auth.example.com")
	t.Setenv("PASSWORDS", "plaintext:test123")
	t.Setenv("TOKEN_SIGNING_KEY", testTokenSigningKey(t))
	t.Setenv("TOKEN_SIGNING_KID", "test-kid")
	t.Setenv("TOKEN_ISSUER", "auth.example.com")
	t.Setenv("TOKEN_ALLOWED_AUDIENCES", "tunnel.mrlin.space,api.example.com")
	t.Setenv("TOKEN_TOTP_REQUIRED_AUDIENCES", "tunnel.mrlin.space")
	t.Setenv("TOKEN_MAX_TTL_SECONDS", "900")
	t.Setenv("TOKEN_DEFAULT_TTL_SECONDS", "300")

	err := config.Initialize(testLogger())
	testza.AssertNoError(t, err)
}

func createAuthenticatedSessionCookie(t *testing.T, store *session.Store, sessionValues map[string]any) string {
	t.Helper()

	app := fiber.New()
	app.Post("/_session", func(ctx *fiber.Ctx) error {
		sess, err := store.Get(ctx)
		testza.AssertNoError(t, err)

		for key, value := range sessionValues {
			sess.Set(key, value)
		}

		testza.AssertNoError(t, auth.Authenticate(sess))
		return ctx.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("POST", "/_session", nil)
	resp, err := app.Test(req)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusOK, resp.StatusCode)

	for _, cookieHeader := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(cookieHeader, auth.SessionCookieName+"=") {
			return strings.SplitN(cookieHeader, ";", 2)[0]
		}
	}

	t.Fatalf("session cookie %q not found in response", auth.SessionCookieName)
	return ""
}

func TestTokenRoute_Success(t *testing.T) {
	setupTokenConfig(t)

	store := setupTestStore()
	app := fiber.New()
	app.Post("/_token", TokenRoute(store))

	sessionCookie := createAuthenticatedSessionCookie(t, store, map[string]any{
		"user_id":    "u_123",
		"user_scope": []string{"forward", "admin"},
		"user_role":  "admin",
		"user_amr":   []string{"warden", "totp"},
		"user_mail":  "user@example.com",
		"user_phone": "13800138000",
		"user_name":  "Kevin",
	})

	req := httptest.NewRequest("POST", "/_token", strings.NewReader(
		`{"audience":"tunnel.mrlin.space","scope":["forward"],"ttl_seconds":600}`,
	))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie)

	httpResp, err := app.Test(req)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusOK, httpResp.StatusCode)

	var tokenResp internal_token.TokenResponse
	err = json.NewDecoder(httpResp.Body).Decode(&tokenResp)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, "Bearer", tokenResp.TokenType)
	testza.AssertEqual(t, 600, tokenResp.ExpiresIn)

	issuer, err := internal_token.NewIssuerFromConfig()
	testza.AssertNoError(t, err)

	claims := &internal_token.Claims{}
	parsed, err := jwt.ParseWithClaims(tokenResp.Token, claims, func(token *jwt.Token) (any, error) {
		return issuer.PublicKey(), nil
	}, jwt.WithIssuer("auth.example.com"), jwt.WithAudience("tunnel.mrlin.space"), jwt.WithValidMethods([]string{"EdDSA"}))
	testza.AssertNoError(t, err)
	testza.AssertTrue(t, parsed.Valid)
	testza.AssertEqual(t, "u_123", claims.Subject)
	testza.AssertEqual(t, "admin", claims.Role)
	testza.AssertEqual(t, "user@example.com", claims.Email)
	testza.AssertEqual(t, 1, len(claims.Scope))
	testza.AssertEqual(t, "forward", claims.Scope[0])
}

func TestTokenRoute_RequiresAuthentication(t *testing.T) {
	setupTokenConfig(t)

	store := setupTestStore()
	app := fiber.New()
	app.Post("/_token", TokenRoute(store))

	req := httptest.NewRequest("POST", "/_token", strings.NewReader(`{"audience":"tunnel.mrlin.space"}`))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestTokenRoute_RejectsAudienceWithoutTOTP(t *testing.T) {
	setupTokenConfig(t)

	store := setupTestStore()
	app := fiber.New()
	app.Post("/_token", TokenRoute(store))

	sessionCookie := createAuthenticatedSessionCookie(t, store, map[string]any{
		"user_id":    "u_123",
		"user_scope": []string{"forward"},
		"user_amr":   []string{"warden"},
	})

	req := httptest.NewRequest("POST", "/_token", strings.NewReader(
		`{"audience":"tunnel.mrlin.space","scope":["forward"]}`,
	))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie)

	resp, err := app.Test(req)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestJWKSRoute_Success(t *testing.T) {
	setupTokenConfig(t)

	handler := JWKSRoute()
	ctx, app := createTestContext("GET", "/_jwks", map[string]string{
		"Accept": "application/json",
	}, "")
	defer app.ReleaseCtx(ctx)

	err := handler(ctx)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusOK, ctx.Response().StatusCode())

	var jwks internal_token.JWKS
	err = json.Unmarshal(ctx.Response().Body(), &jwks)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, 1, len(jwks.Keys))
	testza.AssertEqual(t, "test-kid", jwks.Keys[0].Kid)
	testza.AssertEqual(t, "OKP", jwks.Keys[0].Kty)
}
