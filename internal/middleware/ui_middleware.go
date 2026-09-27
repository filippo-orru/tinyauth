package middleware

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/assets"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

	"github.com/gin-gonic/gin"
)

// loginAutoRedirectQuery mirrors the query parameters the login page cares about
// when deciding whether to redirect straight to the OAuth provider.
type loginAutoRedirectQuery struct {
	LoginFor    string `form:"login_for"`
	OIDCTicket  string `form:"oidc_ticket"`
	OIDCPrompt  string `form:"oidc_prompt"`
	RedirectURI string `form:"redirect_uri"`
}

type UIMiddleware struct {
	uiFs         fs.FS
	uiFileServer http.Handler

	log     *logger.Logger
	config  *model.Config
	runtime *model.RuntimeConfig
	auth    *service.AuthService
}

type UIMiddlewareInput struct {
	dig.In

	Log           *logger.Logger
	Config        *model.Config
	RuntimeConfig *model.RuntimeConfig
	AuthService   *service.AuthService
}

func NewUIMiddleware(i UIMiddlewareInput) (*UIMiddleware, error) {
	m := &UIMiddleware{
		log:     i.Log,
		config:  i.Config,
		runtime: i.RuntimeConfig,
		auth:    i.AuthService,
	}

	ui, err := fs.Sub(assets.FrontendAssets, "dist")

	if err != nil {
		return nil, fmt.Errorf("failed to load ui assets: %w", err)
	}

	m.uiFs = ui
	m.uiFileServer = http.FileServerFS(ui)

	return m, nil
}

func (m *UIMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/")
		segment := strings.SplitN(path, "/", 2)[0]

		switch segment {
		case "api", "resources", ".well-known", "authorize":
			c.Next()
			return
		case "robots.txt":
			c.Writer.Header().Set("Content-Type", "text/plain")
			c.Writer.WriteHeader(http.StatusOK)
			c.Writer.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		case "login":
			if m.tryOAuthAutoRedirect(c) {
				return
			}
		}

		_, err := fs.Stat(m.uiFs, path)

		// Enough for one authentication flow
		maxAge := 15 * time.Minute

		if os.IsNotExist(err) {
			c.Request.URL.Path = "/"
		} else if strings.HasPrefix(path, "assets/") {
			// assets are named with a hash and can be cached for a long time
			maxAge = 30 * 24 * time.Hour
		}

		c.Writer.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
		m.uiFileServer.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

// tryOAuthAutoRedirect checks whether the login page request qualifies for an
// automatic redirect straight to the configured OAuth provider (skipping the
// frontend "redirecting..." screen entirely) and, if so, issues the redirect.
// It returns true if the request was handled (i.e. a redirect was issued).
func (m *UIMiddleware) tryOAuthAutoRedirect(c *gin.Context) bool {
	if m.config.OAuth.AutoRedirect == "" {
		return false
	}

	providerConfigured := false

	for _, provider := range m.runtime.ConfiguredProviders {
		if provider.ID == m.config.OAuth.AutoRedirect {
			providerConfigured = true
			break
		}
	}

	if !providerConfigured {
		return false
	}

	var query loginAutoRedirectQuery

	if err := c.ShouldBindQuery(&query); err != nil {
		return false
	}

	// Nothing to continue to, this is likely a direct visit to the login page
	// so let the frontend render its normal login screen.
	if query.RedirectURI == "" && query.OIDCTicket == "" {
		return false
	}

	// The user explicitly asked to see the login screen again (e.g. OIDC
	// "prompt=login" or switching accounts), so don't auto-redirect.
	if query.OIDCPrompt == "login" {
		return false
	}

	userContext, err := new(model.UserContext).NewFromGin(c)

	if err == nil && userContext.IsAuthenticated() {
		return false
	}

	isOidcRequest := query.LoginFor == "oidc"

	callbackParams := service.OAuthCallbackParams{
		LoginFor:    query.LoginFor,
		OIDCTicket:  query.OIDCTicket,
		RedirectURI: query.RedirectURI,
	}

	if !isOidcRequest {
		if !utils.IsRedirectSafe(m.config, m.runtime, m.log, callbackParams.RedirectURI) {
			m.log.App.Warn().Str("redirectUri", callbackParams.RedirectURI).Msg("Unsafe redirect URI, ignoring auto redirect")
			callbackParams.RedirectURI = ""
		}
	}

	sessionId, err := m.auth.NewOAuthSession(m.config.OAuth.AutoRedirect, callbackParams)

	if err != nil {
		m.log.App.Error().Err(err).Msg("Failed to create new OAuth session for auto redirect")
		return false
	}

	authUrl, err := m.auth.GetOAuthURL(sessionId)

	if err != nil {
		m.log.App.Error().Err(err).Msg("Failed to get OAuth URL for auto redirect")
		return false
	}

	c.SetCookie(m.runtime.OAuthSessionCookieName, sessionId, int(time.Hour.Seconds()), "/", utils.GetSessionCookieDomain(m.config, m.runtime), m.config.Auth.SecureCookie, true)
	c.Redirect(http.StatusFound, authUrl)
	c.Abort()

	return true
}
