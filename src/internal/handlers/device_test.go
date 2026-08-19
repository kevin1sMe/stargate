package handlers

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/soulteary/stargate/src/internal/deviceauth"
)

func TestDeviceTokenNotFoundIsExpiredToken(t *testing.T) {
	ctx, app := createTestContext("POST", "/oauth/token", nil, "")
	defer app.ReleaseCtx(ctx)
	if err := handleDeviceTokenError(ctx, deviceauth.ErrNotFound, true); err != nil {
		t.Fatal(err)
	}
	if ctx.Response().StatusCode() != fiber.StatusBadRequest || !strings.Contains(string(ctx.Response().Body()), "expired_token") {
		t.Fatalf("unexpected response: status=%d body=%s", ctx.Response().StatusCode(), ctx.Response().Body())
	}
}

func TestRefreshTokenNotFoundIsInvalidGrant(t *testing.T) {
	ctx, app := createTestContext("POST", "/oauth/token", nil, "")
	defer app.ReleaseCtx(ctx)
	if err := handleDeviceTokenError(ctx, deviceauth.ErrNotFound, false); err != nil {
		t.Fatal(err)
	}
	if ctx.Response().StatusCode() != fiber.StatusBadRequest || !strings.Contains(string(ctx.Response().Body()), "invalid_grant") {
		t.Fatalf("unexpected response: status=%d body=%s", ctx.Response().StatusCode(), ctx.Response().Body())
	}
}
