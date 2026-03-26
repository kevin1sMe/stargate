package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/soulteary/stargate/src/internal/auth"
	"github.com/soulteary/stargate/src/internal/token"
)

// SessionStoreForToken is the minimal interface required by TokenRoute to get session.
type SessionStoreForToken interface {
	Get(ctx *fiber.Ctx) (*session.Session, error)
}

func TokenRoute(store SessionStoreForToken) func(c *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		sess, err := store.Get(ctx)
		if err != nil {
			return SendErrorResponse(ctx, fiber.StatusInternalServerError, "failed to access session store")
		}
		if !auth.IsAuthenticated(sess) {
			return SendErrorResponse(ctx, fiber.StatusUnauthorized, "authentication required")
		}

		var req token.IssueTokenRequest
		if err := ctx.BodyParser(&req); err != nil {
			return SendErrorResponse(ctx, fiber.StatusBadRequest, "invalid token request payload")
		}

		issuer, err := token.NewIssuerFromConfig()
		if err != nil {
			return handleTokenError(ctx, err)
		}

		resp, err := issuer.Issue(token.SessionSubject{
			UserID: sessionString(sess, "user_id"),
			Phone:  sessionString(sess, "user_phone"),
			Email:  sessionString(sess, "user_mail"),
			Role:   sessionString(sess, "user_role"),
			Name:   sessionString(sess, "user_name"),
			AMR:    sessionStringSlice(sess, "user_amr"),
			Scopes: sessionStringSlice(sess, "user_scope"),
		}, req)
		if err != nil {
			return handleTokenError(ctx, err)
		}

		return ctx.Status(fiber.StatusOK).JSON(resp)
	}
}

func JWKSRoute() func(c *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		issuer, err := token.NewIssuerFromConfig()
		if err != nil {
			return handleTokenError(ctx, err)
		}
		return ctx.Status(fiber.StatusOK).JSON(issuer.JWKS())
	}
}

func handleTokenError(ctx *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, token.ErrTokenNotConfigured):
		return SendErrorResponse(ctx, fiber.StatusServiceUnavailable, "token issuer is not configured")
	case errors.Is(err, token.ErrInvalidAudience):
		return SendErrorResponse(ctx, fiber.StatusBadRequest, "invalid or disallowed audience")
	case errors.Is(err, token.ErrInvalidTTL):
		return SendErrorResponse(ctx, fiber.StatusBadRequest, "invalid ttl_seconds")
	case errors.Is(err, token.ErrScopeNotAllowed):
		return SendErrorResponse(ctx, fiber.StatusForbidden, "requested scope exceeds session scope")
	case errors.Is(err, token.ErrTOTPRequired):
		return SendErrorResponse(ctx, fiber.StatusForbidden, "totp authentication is required for this audience")
	case errors.Is(err, token.ErrSessionMissingSubject):
		return SendErrorResponse(ctx, fiber.StatusUnauthorized, "session does not contain a user_id")
	default:
		return SendErrorResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}
}

func sessionString(sess *session.Session, key string) string {
	value, _ := sess.Get(key).(string)
	return strings.TrimSpace(value)
}

func sessionStringSlice(sess *session.Session, key string) []string {
	value := sess.Get(key)
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
				result = append(result, strings.TrimSpace(str))
			}
		}
		return result
	default:
		return nil
	}
}
