package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
	"github.com/rs/zerolog"

	kesselv2 "github.com/project-kessel/inventory-api/api/kessel/inventory/v1beta2"
	"github.com/project-kessel/inventory-client-go/common"
	client "github.com/project-kessel/inventory-client-go/v1beta2"
)

// KesselClientWrapper implements rbac.ClientWrapper interface using Kessel RBAC v2
type KesselClientWrapper struct {
	client      *client.InventoryClient
	tokenClient *common.TokenClient
	rbacUrl     string
}

// NewKesselClientWrapper creates a new Kessel client wrapper from config
func NewKesselClientWrapper(cfg *config.Configuration) (ClientWrapper, error) {
	if cfg.Clients.KesselUrl == "" {
		return nil, fmt.Errorf("kessel URL is required")
	}

	// Configure Kessel client options
	options := []func(*common.Config){
		common.WithgRPCUrl(cfg.Clients.KesselUrl),
		common.WithTLSInsecure(cfg.Clients.KesselInsecure),
	}

	if cfg.Clients.KesselAuthEnabled {
		options = append(options, common.WithAuthEnabled(
			cfg.Clients.KesselAuthClientId,
			cfg.Clients.KesselAuthClientSecret,
			cfg.Clients.KesselAuthOidcIssuer,
		))
	}

	// Create Kessel client
	kesselConfig := common.NewConfig(options...)
	kesselClient, err := client.New(kesselConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kessel client: %w", err)
	}

	// Create token client if auth is enabled (for RBAC API calls)
	var tokenClient *common.TokenClient
	if cfg.Clients.KesselAuthEnabled {
		tokenClient = common.NewTokenClient(kesselConfig)
	}

	return &KesselClientWrapper{
		client:      kesselClient,
		tokenClient: tokenClient,
		rbacUrl:     cfg.Clients.RbacBaseUrl, // Use RBAC URL for workspace lookup
	}, nil
}

// Allowed checks if the user has the required permission via Kessel
func (k *KesselClientWrapper) Allowed(ctx context.Context, resource Resource, verb Verb) (bool, error) {
	logger := zerolog.Ctx(ctx)

	// Get root workspace ID for the organization
	workspaceID, err := k.getRootWorkspaceID(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get root workspace ID")
		return false, err
	}

	// Map resource/verb to Kessel permission
	permission := mapToKesselPermission(resource, verb)
	if permission == "" {
		logger.Error().Str("resource", string(resource)).Str("verb", string(verb)).Msg("No Kessel permission mapping found")
		return false, fmt.Errorf("no permission mapping for resource=%s verb=%s", resource, verb)
	}

	// Build the authorization request
	object := &kesselv2.ResourceReference{
		ResourceType: "workspace",
		ResourceId:   workspaceID,
		Reporter: &kesselv2.ReporterReference{
			Type: "rbac",
		},
	}

	subject := k.buildSubjectReference(ctx)

	// Use Check for read operations, CheckForUpdate for writes/uploads
	var allowed bool
	if verb == RbacVerbRead {
		resp, err := k.client.KesselInventoryService.Check(ctx, &kesselv2.CheckRequest{
			Object:   object,
			Relation: permission,
			Subject:  subject,
		})
		if err != nil {
			logger.Error().Err(err).Str("permission", permission).Msg("Kessel Check failed")
			return false, err
		}
		allowed = resp.Allowed == kesselv2.Allowed_ALLOWED_TRUE
	} else {
		resp, err := k.client.KesselInventoryService.CheckForUpdate(ctx, &kesselv2.CheckForUpdateRequest{
			Object:   object,
			Relation: permission,
			Subject:  subject,
		})
		if err != nil {
			logger.Error().Err(err).Str("permission", permission).Msg("Kessel CheckForUpdate failed")
			return false, err
		}
		allowed = resp.Allowed == kesselv2.Allowed_ALLOWED_TRUE
	}

	logger.Debug().
		Bool("allowed", allowed).
		Str("resource", string(resource)).
		Str("verb", string(verb)).
		Str("permission", permission).
		Str("workspace_id", workspaceID).
		Msg("Kessel authorization check completed")

	return allowed, nil
}

// Helper functions

// buildSubjectReference creates a subject reference for the current user
func (k *KesselClientWrapper) buildSubjectReference(ctx context.Context) *kesselv2.SubjectReference {
	id := identity.GetIdentity(ctx)

	var principalID string
	switch id.Identity.Type {
	case "User":
		principalID = id.Identity.User.UserID
	case "ServiceAccount":
		principalID = id.Identity.ServiceAccount.UserId
	}

	return &kesselv2.SubjectReference{
		Resource: &kesselv2.ResourceReference{
			ResourceType: "principal",
			ResourceId:   fmt.Sprintf("redhat/%s", principalID),
			Reporter: &kesselv2.ReporterReference{
				Type: "rbac",
			},
		},
	}
}

// workspace represents a workspace in the RBAC API response
type workspace struct {
	ID string `json:"id"`
}

// workspaceResponse represents the RBAC API response structure
type workspaceResponse struct {
	Data []workspace `json:"data"`
}

// getRootWorkspaceID looks up the root workspace ID for the organization
func (k *KesselClientWrapper) getRootWorkspaceID(ctx context.Context) (string, error) {
	logger := zerolog.Ctx(ctx)

	if k.rbacUrl == "" {
		return "", fmt.Errorf("RBAC URL not configured")
	}

	id := identity.GetIdentity(ctx)
	orgID := id.Identity.Internal.OrgID

	url := fmt.Sprintf("%s/api/rbac/v2/workspaces/?type=root", k.rbacUrl)

	logger.Debug().
		Str("org_id", orgID).
		Str("url", url).
		Msg("Looking up root workspace ID")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("x-rh-rbac-org-id", orgID)

	// Add authentication token if available
	if k.tokenClient != nil {
		token, err := k.tokenClient.GetToken()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to obtain authentication token")
			return "", fmt.Errorf("error obtaining authentication token: %w", err)
		}
		req.Header.Add("authorization", fmt.Sprintf("bearer %s", token.AccessToken))
		logger.Debug().Msg("Added authentication token to request")
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error().Err(err).Str("url", url).Msg("HTTP request failed")
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error().
			Int("status_code", resp.StatusCode).
			Str("url", url).
			Msg("Unexpected HTTP status code")
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read response body")
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	var response workspaceResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		logger.Error().Err(err).Str("body", string(body)).Msg("Failed to unmarshal response")
		return "", fmt.Errorf("error unmarshalling response: %w", err)
	}

	if len(response.Data) != 1 {
		logger.Error().
			Int("count", len(response.Data)).
			Str("org_id", orgID).
			Msg("Unexpected number of root workspaces")
		return "", fmt.Errorf("unexpected number of root workspaces: %d", len(response.Data))
	}

	workspaceID := response.Data[0].ID
	logger.Debug().
		Str("workspace_id", workspaceID).
		Str("org_id", orgID).
		Msg("Successfully retrieved root workspace ID")

	return workspaceID, nil
}

// mapToKesselPermission maps RBAC v1 resource/verb combinations to Kessel v2 permissions
func mapToKesselPermission(resource Resource, verb Verb) string {
	// Skip invalid resources
	if resource == ResourceAny || resource == ResourceUndefined || string(resource) == "" {
		return ""
	}

	// Map verb to action suffix
	var actionSuffix string
	switch verb {
	case RbacVerbRead:
		actionSuffix = "view"
	case RbacVerbWrite:
		actionSuffix = "edit"
	case RbacVerbUpload:
		actionSuffix = "upload"
	default:
		return ""
	}

	return fmt.Sprintf("content_sources_%s_%s", string(resource), actionSuffix)
}
