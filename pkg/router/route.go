package router

import (
	"context"
	"time"

	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/content-services/content-sources-backend/pkg/handler"
	"github.com/content-services/content-sources-backend/pkg/instrumentation"
	"github.com/content-services/content-sources-backend/pkg/middleware"
	"github.com/content-services/content-sources-backend/pkg/rbac"
	"github.com/content-services/lecho/v3"
	"github.com/labstack/echo/v4"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func ConfigureEcho(ctx context.Context, allRoutes bool) *echo.Echo {
	e := echo.New()
	// Add global middlewares
	echoLogger := lecho.From(log.Logger,
		lecho.WithTimestamp(),
		lecho.WithCaller(),
	)

	e.Use(middleware.AddRequestId)
	e.Use(lecho.Middleware(lecho.Config{
		Logger:              echoLogger,
		RequestIDHeader:     config.HeaderRequestId,
		RequestIDKey:        config.RequestIdLoggingKey,
		Skipper:             config.SkipLogging,
		RequestLatencyLevel: zerolog.WarnLevel,
		RequestLatencyLimit: 500 * time.Millisecond,
	}))
	e.Use(middleware.ExtractStatus) // Must be after lecho
	e.Use(middleware.EnforceJSONContentType)
	e.Use(middleware.LogServerErrorRequest)

	// Add routes
	handler.RegisterPing(e)
	if allRoutes {
		handler.RegisterRoutes(ctx, e)
	}

	// Set error handler
	e.HTTPErrorHandler = config.CustomHTTPErrorHandler
	return e
}

func ConfigureEchoWithMetrics(ctx context.Context, metrics *instrumentation.Metrics) *echo.Echo {
	e := ConfigureEcho(ctx, true)

	// Add additional global middlewares
	e.Use(middleware.WrapMiddlewareWithSkipper(identity.EnforceIdentity, middleware.SkipMiddleware))
	e.Use(middleware.EnforceOrgId)
	e.Use(middleware.CreateMetricsMiddleware(metrics))
	// Configure authorization middleware - prefer Kessel over RBAC v1
	var authClient rbac.ClientWrapper
	var authType string

	if config.Get().Clients.KesselEnabled {
		// Configure Kessel client
		var err error
		authClient, err = rbac.NewKesselClientWrapper(config.Get())
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create Kessel client")
		}
		authType = "Kessel"
		log.Info().Msgf("Authorization: Using Kessel (URL=%s, insecure=%t)",
			config.Get().Clients.KesselUrl, config.Get().Clients.KesselInsecure)

	} else if config.Get().Clients.RbacEnabled {
		// Configure RBAC v1 client
		rbacBaseUrl := config.Get().Clients.RbacBaseUrl
		rbacTimeout := time.Duration(int64(config.Get().Clients.RbacTimeout) * int64(time.Second))
		authClient = rbac.NewClientWrapperImpl(rbacBaseUrl, rbacTimeout)
		authType = "RBAC v1"
		log.Info().Msgf("Authorization: Using RBAC v1 (URL=%s, timeout=%d secs)",
			rbacBaseUrl, rbacTimeout/time.Second)
	}

	if authClient != nil {
		e.Use(
			middleware.NewRbac(
				middleware.Rbac{
					BaseUrl:        config.Get().Clients.RbacBaseUrl, // Still needed for middleware compatibility
					Skipper:        middleware.SkipMiddleware,
					PermissionsMap: rbac.ServicePermissions,
					Client:         authClient,
				},
			),
		)
		log.Info().Msgf("Authorization middleware configured with %s", authType)
	} else {
		log.Warn().Msg("No authorization middleware configured - both Kessel and RBAC v1 are disabled")
	}
	return e
}
