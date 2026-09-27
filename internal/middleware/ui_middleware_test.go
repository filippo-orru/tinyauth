package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestUIMiddleware_OAuthAutoRedirect(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	runtime.OAuthProviders = map[string]model.OAuthServiceConfig{
		"google": {
			Name:         "Google",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			AuthURL:      "https://accounts.google.com/o/oauth2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			RedirectURL:  "https://tinyauth.example.com/api/oauth/callback/google",
		},
	}

	runtime.ConfiguredProviders = append(runtime.ConfiguredProviders, model.Provider{
		Name:  "Google",
		ID:    "google",
		OAuth: true,
	})

	runtime.AppURL = "https://tinyauth.example.com"
	runtime.SessionCookieName = "tinyauth-session"
	runtime.OAuthSessionCookieName = "tinyauth-oauth-session"

	ctx := context.TODO()
	dg := ding.New(ctx)

	broker := service.NewOAuthBrokerService(service.OAuthBrokerServiceInput{
		Log:     log,
		Runtime: &runtime,
		Ctx:     ctx,
	})

	store := memory.New()

	policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	require.NoError(t, err)

	authService, err := service.NewAuthService(service.AuthServiceInput{
		Log:          log,
		Config:       &cfg,
		Runtime:      &runtime,
		Ctx:          ctx,
		Ding:         dg,
		LDAP:         nil,
		Queries:      store,
		OAuthBroker:  broker,
		Tailscale:    nil,
		PolicyEngine: policyEngine,
	})
	require.NoError(t, err)

	newRouter := func() *gin.Engine {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			// Simulate the ContextMiddleware not finding an authenticated user
			// (no cookie set) unless a test explicitly injects a context.
			c.Next()
		})

		m, err := NewUIMiddleware(UIMiddlewareInput{
			Log:           log,
			Config:        &cfg,
			RuntimeConfig: &runtime,
			AuthService:   authService,
		})
		require.NoError(t, err)

		router.Use(m.Middleware())
		return router
	}

	type testCase struct {
		description    string
		autoRedirect   string
		path           string
		setupRequest   func(req *http.Request)
		expectRedirect bool
	}

	tests := []testCase{
		{
			description:    "No auto redirect configured serves normal page",
			autoRedirect:   "none",
			path:           "/login?redirect_uri=https://tinyauth.example.com/app",
			expectRedirect: false,
		},
		{
			description:    "Auto redirect configured with redirect_uri redirects to provider",
			autoRedirect:   "google",
			path:           "/login?redirect_uri=https://tinyauth.example.com/app&login_for=app",
			expectRedirect: true,
		},
		{
			description:    "Auto redirect configured with oidc_ticket redirects to provider",
			autoRedirect:   "google",
			path:           "/login?oidc_ticket=some-ticket&login_for=oidc",
			expectRedirect: true,
		},
		{
			description:    "Auto redirect configured but no redirect_uri or oidc_ticket does not redirect",
			autoRedirect:   "google",
			path:           "/login",
			expectRedirect: false,
		},
		{
			description:    "Auto redirect configured but prompt=login does not redirect",
			autoRedirect:   "google",
			path:           "/login?redirect_uri=https://tinyauth.example.com/app&oidc_prompt=login",
			expectRedirect: false,
		},
		{
			description:    "Auto redirect configured for a provider that is not configured does not redirect",
			autoRedirect:   "microsoft",
			path:           "/login?redirect_uri=https://tinyauth.example.com/app",
			expectRedirect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			cfg.OAuth.AutoRedirect = tc.autoRedirect

			router := newRouter()

			req := httptest.NewRequest("GET", tc.path, nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if tc.expectRedirect {
				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, "accounts.google.com")

				cookies := recorder.Result().Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, runtime.OAuthSessionCookieName, cookies[0].Name)
			} else {
				assert.NotEqual(t, http.StatusFound, recorder.Code)
			}
		})
	}
}

func TestUIMiddleware_OAuthAutoRedirect_SkipsAuthenticatedUsers(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)
	cfg.OAuth.AutoRedirect = "google"

	runtime.OAuthProviders = map[string]model.OAuthServiceConfig{
		"google": {
			Name:         "Google",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			AuthURL:      "https://accounts.google.com/o/oauth2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			RedirectURL:  "https://tinyauth.example.com/api/oauth/callback/google",
		},
	}
	runtime.ConfiguredProviders = append(runtime.ConfiguredProviders, model.Provider{
		Name:  "Google",
		ID:    "google",
		OAuth: true,
	})
	runtime.AppURL = "https://tinyauth.example.com"

	ctx := context.TODO()
	dg := ding.New(ctx)

	broker := service.NewOAuthBrokerService(service.OAuthBrokerServiceInput{
		Log:     log,
		Runtime: &runtime,
		Ctx:     ctx,
	})

	store := memory.New()

	policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	require.NoError(t, err)

	authService, err := service.NewAuthService(service.AuthServiceInput{
		Log:          log,
		Config:       &cfg,
		Runtime:      &runtime,
		Ctx:          ctx,
		Ding:         dg,
		LDAP:         nil,
		Queries:      store,
		OAuthBroker:  broker,
		Tailscale:    nil,
		PolicyEngine: policyEngine,
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local:         &model.LocalContext{},
		})
		c.Next()
	})

	m, err := NewUIMiddleware(UIMiddlewareInput{
		Log:           log,
		Config:        &cfg,
		RuntimeConfig: &runtime,
		AuthService:   authService,
	})
	require.NoError(t, err)
	router.Use(m.Middleware())

	req := httptest.NewRequest("GET", "/login?redirect_uri=https://tinyauth.example.com/app", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.NotEqual(t, http.StatusFound, recorder.Code)
}
