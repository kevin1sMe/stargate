package handlers

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/soulteary/stargate/src/internal/auth"
	"github.com/soulteary/stargate/src/internal/deviceauth"
	"github.com/soulteary/stargate/src/internal/token"
)

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func DeviceAuthorizationRoute(service *deviceauth.Service) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if !service.Enabled() {
			return ctx.SendStatus(fiber.StatusNotFound)
		}
		clientID := strings.TrimSpace(ctx.FormValue("client_id"))
		scopes := strings.Fields(ctx.FormValue("scope"))
		verificationURI := forwardedBaseURL(ctx) + "/device"
		response, err := service.Start(ctx.Context(), clientID, scopes, verificationURI, time.Now())
		if err != nil {
			if errors.Is(err, deviceauth.ErrInvalidClient) {
				return oauthError(ctx, fiber.StatusBadRequest, "invalid_client", "unknown device client")
			}
			if errors.Is(err, deviceauth.ErrInvalidScope) {
				return oauthError(ctx, fiber.StatusBadRequest, "invalid_scope", "requested scope is not allowed")
			}
			return oauthError(ctx, fiber.StatusInternalServerError, "server_error", "failed to create device authorization")
		}
		ctx.Set(fiber.HeaderCacheControl, "no-store")
		return ctx.Status(fiber.StatusOK).JSON(response)
	}
}

func DeviceVerificationRoute(service *deviceauth.Service, store SessionStoreForToken) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if !service.Enabled() {
			return ctx.SendStatus(fiber.StatusNotFound)
		}
		code := strings.TrimSpace(ctx.Query("user_code"))
		if code == "" {
			return ctx.Render("device", fiber.Map{"Lookup": true, "Title": "Device authorization"})
		}
		grant, err := service.FindByUserCode(ctx.Context(), code, time.Now())
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).Render("device", fiber.Map{
				"Error": "The code is invalid or expired.", "Title": "Device authorization",
			})
		}
		sess, err := store.Get(ctx)
		if err != nil {
			return SendErrorResponse(ctx, fiber.StatusInternalServerError, "failed to access session store")
		}
		if !auth.IsAuthenticated(sess) {
			returnTo := "/device?user_code=" + url.QueryEscape(grant.UserCode)
			return ctx.Redirect("/_login?return_to=" + url.QueryEscape(returnTo))
		}
		if grant.Status != deviceauth.StatusPending {
			return ctx.Render("device", fiber.Map{"Complete": true, "Title": "Device authorization"})
		}
		return ctx.Render("device", fiber.Map{
			"Title": "Device authorization", "Grant": grant, "UserCode": grant.UserCode,
			"ClientID": grant.ClientID, "Audience": grant.TokenRequest.Audience,
			"Scopes": strings.Join(grant.TokenRequest.Scope, " "),
		})
	}
}

func DeviceApprovalRoute(service *deviceauth.Service, store SessionStoreForToken) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if !service.Enabled() {
			return ctx.SendStatus(fiber.StatusNotFound)
		}
		sess, err := store.Get(ctx)
		if err != nil {
			return SendErrorResponse(ctx, fiber.StatusInternalServerError, "failed to access session store")
		}
		if !auth.IsAuthenticated(sess) {
			return SendErrorResponse(ctx, fiber.StatusUnauthorized, "authentication required")
		}
		approved := ctx.FormValue("decision") == "approve"
		subject := token.SessionSubject{
			UserID: sessionString(sess, "user_id"), Phone: sessionString(sess, "user_phone"),
			Email: sessionString(sess, "user_mail"), Role: sessionString(sess, "user_role"),
			Name: sessionString(sess, "user_name"), AMR: sessionStringSlice(sess, "user_amr"),
			Scopes: sessionStringSlice(sess, "user_scope"),
		}
		_, err = service.Resolve(ctx.Context(), ctx.FormValue("user_code"), &subject, approved, time.Now())
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).Render("device", fiber.Map{"Error": "The code is invalid, expired, or already used.", "Title": "Device authorization"})
		}
		message := "Authorization denied. You may close this window."
		if approved {
			message = "Authorization complete. Return to your terminal."
		}
		return ctx.Render("device", fiber.Map{"Complete": true, "Message": message, "Title": "Device authorization"})
	}
}

func OAuthTokenRoute(service *deviceauth.Service) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if !service.Enabled() {
			return ctx.SendStatus(fiber.StatusNotFound)
		}
		grantType := ctx.FormValue("grant_type")
		clientID := ctx.FormValue("client_id")
		var response *deviceauth.OAuthTokenResponse
		var err error
		switch grantType {
		case deviceCodeGrantType:
			response, err = service.ExchangeDevice(ctx.Context(), clientID, ctx.FormValue("device_code"), time.Now())
			if err != nil {
				return handleDeviceTokenError(ctx, err, true)
			}
		case "refresh_token":
			response, err = service.ExchangeRefresh(ctx.Context(), clientID, ctx.FormValue("refresh_token"), time.Now())
			if err != nil {
				return handleDeviceTokenError(ctx, err, false)
			}
		default:
			return oauthError(ctx, fiber.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		}
		ctx.Set(fiber.HeaderCacheControl, "no-store")
		ctx.Set(fiber.HeaderPragma, "no-cache")
		return ctx.Status(fiber.StatusOK).JSON(response)
	}
}

func handleDeviceTokenError(ctx *fiber.Ctx, err error, deviceGrant bool) error {
	switch {
	case errors.Is(err, deviceauth.ErrAuthorizationWait):
		return oauthError(ctx, fiber.StatusBadRequest, "authorization_pending", "authorization is still pending")
	case errors.Is(err, deviceauth.ErrSlowDown):
		return oauthError(ctx, fiber.StatusBadRequest, "slow_down", "polling too quickly")
	case errors.Is(err, deviceauth.ErrAccessDenied):
		return oauthError(ctx, fiber.StatusBadRequest, "access_denied", "authorization was denied")
	case errors.Is(err, deviceauth.ErrExpired), errors.Is(err, deviceauth.ErrAlreadyConsumed), deviceGrant && errors.Is(err, deviceauth.ErrNotFound):
		return oauthError(ctx, fiber.StatusBadRequest, "expired_token", "device code expired or was already used")
	case errors.Is(err, deviceauth.ErrInvalidClient):
		return oauthError(ctx, fiber.StatusBadRequest, "invalid_client", "unknown device client")
	case errors.Is(err, deviceauth.ErrInvalidRefresh), errors.Is(err, deviceauth.ErrNotFound):
		return oauthError(ctx, fiber.StatusBadRequest, "invalid_grant", "invalid device or refresh token")
	default:
		return oauthError(ctx, fiber.StatusInternalServerError, "server_error", "token exchange failed")
	}
}

func oauthError(ctx *fiber.Ctx, status int, code, description string) error {
	ctx.Set(fiber.HeaderCacheControl, "no-store")
	return ctx.Status(status).JSON(fiber.Map{"error": code, "error_description": description})
}

func forwardedBaseURL(ctx *fiber.Ctx) string {
	proto := GetForwardedProto(ctx)
	if proto == "" {
		proto = ctx.Protocol()
	}
	return proto + "://" + GetForwardedHost(ctx)
}
