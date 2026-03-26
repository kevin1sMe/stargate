package handlers

import (
	"encoding/json"
	"testing"

	"github.com/MarvinJWendt/testza"
	"github.com/gofiber/fiber/v2"
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

func TestTokenRoute_Success(t *testing.T) {
	setupTokenConfig(t)

	store := setupTestStore()
	handler := TokenRoute(store)

	ctx, app := createTestContext("POST", "/_token", map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}, `{"audience":"tunnel.mrlin.space","scope":["forward"],"ttl_seconds":600}`)
	defer app.ReleaseCtx(ctx)

	sess, err := store.Get(ctx)
	testza.AssertNoError(t, err)
	testza.AssertNoError(t, auth.Authenticate(sess))
	sess.Set("user_id", "u_123")
	sess.Set("user_scope", []string{"forward", "admin"})
	sess.Set("user_role", "admin")
	sess.Set("user_amr", []string{"warden", "totp"})
	sess.Set("user_mail", "user@example.com")
	sess.Set("user_phone", "13800138000")
	sess.Set("user_name", "Kevin")

	err = handler(ctx)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusOK, ctx.Response().StatusCode())

	var resp internal_token.TokenResponse
	err = json.Unmarshal(ctx.Response().Body(), &resp)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, "Bearer", resp.TokenType)
	testza.AssertEqual(t, 600, resp.ExpiresIn)

	issuer, err := internal_token.NewIssuerFromConfig()
	testza.AssertNoError(t, err)

	claims := &internal_token.Claims{}
	parsed, err := jwt.ParseWithClaims(resp.Token, claims, func(token *jwt.Token) (any, error) {
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
	handler := TokenRoute(store)

	ctx, app := createTestContext("POST", "/_token", map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}, `{"audience":"tunnel.mrlin.space"}`)
	defer app.ReleaseCtx(ctx)

	err := handler(ctx)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusUnauthorized, ctx.Response().StatusCode())
}

func TestTokenRoute_RejectsAudienceWithoutTOTP(t *testing.T) {
	setupTokenConfig(t)

	store := setupTestStore()
	handler := TokenRoute(store)

	ctx, app := createTestContext("POST", "/_token", map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}, `{"audience":"tunnel.mrlin.space","scope":["forward"]}`)
	defer app.ReleaseCtx(ctx)

	sess, err := store.Get(ctx)
	testza.AssertNoError(t, err)
	testza.AssertNoError(t, auth.Authenticate(sess))
	sess.Set("user_id", "u_123")
	sess.Set("user_scope", []string{"forward"})
	sess.Set("user_amr", []string{"warden"})

	err = handler(ctx)
	testza.AssertNoError(t, err)
	testza.AssertEqual(t, fiber.StatusForbidden, ctx.Response().StatusCode())
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
