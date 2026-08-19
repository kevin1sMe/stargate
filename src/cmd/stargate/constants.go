package main

const (
	// DefaultPort is the default server port
	DefaultPort = ":80"

	// RouteRoot is the root route
	RouteRoot = "/"
	// RouteLogin is the login page route
	RouteLogin = "/_login"
	// RouteLogout is the logout route
	RouteLogout = "/_logout"
	// RouteSessionExchange is the session exchange route
	RouteSessionExchange = "/_session_exchange"
	// RouteAuth is the authentication check route
	RouteAuth = "/_auth"
	// RouteToken is the session-to-token exchange route
	RouteToken = "/_token"
	// RouteJWKS is the token public key route
	RouteJWKS = "/_jwks"
	// RouteDeviceAuthorization starts an OAuth device authorization request.
	RouteDeviceAuthorization = "/oauth/device/authorization"
	// RouteOAuthToken exchanges device and refresh grants for access tokens.
	RouteOAuthToken = "/oauth/token"
	// RouteDeviceVerification is the browser-facing device confirmation page.
	RouteDeviceVerification = "/device"
	// RouteHealth is the health check route
	RouteHealth = "/health"

	// StaticAssetsPath is the static assets path
	StaticAssetsPath = "./internal/web/templates/assets"
	// FaviconPath is the favicon file path
	FaviconPath = "./internal/web/templates/assets/favicon.ico"
)
