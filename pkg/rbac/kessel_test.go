package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKesselClientWrapper(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Configuration
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with auth enabled",
			config: &config.Configuration{
				Clients: config.Clients{
					KesselUrl:              "http://kessel.example.com",
					KesselInsecure:         true,
					KesselAuthEnabled:      true,
					KesselAuthClientId:     "test-client",
					KesselAuthClientSecret: "test-secret",
					KesselAuthOidcIssuer:   "http://auth.example.com",
					RbacBaseUrl:            "http://rbac.example.com",
				},
			},
			expectError: false,
		},
		{
			name: "success with auth disabled",
			config: &config.Configuration{
				Clients: config.Clients{
					KesselUrl:         "http://kessel.example.com",
					KesselInsecure:    true,
					KesselAuthEnabled: false,
					RbacBaseUrl:       "http://rbac.example.com",
				},
			},
			expectError: false,
		},
		{
			name: "error with missing URL",
			config: &config.Configuration{
				Clients: config.Clients{
					KesselUrl: "",
				},
			},
			expectError: true,
			errorMsg:    "kessel URL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, err := NewKesselClientWrapper(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, wrapper)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, wrapper)

				kesselWrapper, ok := wrapper.(*KesselClientWrapper)
				require.True(t, ok)
				assert.NotNil(t, kesselWrapper.client)
				assert.Equal(t, tt.config.Clients.RbacBaseUrl, kesselWrapper.rbacUrl)
			}
		})
	}
}

func TestMapToKesselPermission(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
		verb     Verb
		expected string
	}{
		// Valid combinations
		{
			name:     "repositories read",
			resource: ResourceRepositories,
			verb:     RbacVerbRead,
			expected: "content_sources_repositories_view",
		},
		{
			name:     "repositories write",
			resource: ResourceRepositories,
			verb:     RbacVerbWrite,
			expected: "content_sources_repositories_edit",
		},
		{
			name:     "repositories upload",
			resource: ResourceRepositories,
			verb:     RbacVerbUpload,
			expected: "content_sources_repositories_upload",
		},
		{
			name:     "templates read",
			resource: ResourceTemplates,
			verb:     RbacVerbRead,
			expected: "content_sources_templates_view",
		},
		{
			name:     "templates write",
			resource: ResourceTemplates,
			verb:     RbacVerbWrite,
			expected: "content_sources_templates_edit",
		},
		// Invalid combinations
		{
			name:     "invalid resource",
			resource: ResourceAny,
			verb:     RbacVerbRead,
			expected: "",
		},
		{
			name:     "undefined resource",
			resource: ResourceUndefined,
			verb:     RbacVerbRead,
			expected: "",
		},
		{
			name:     "empty resource",
			resource: Resource(""),
			verb:     RbacVerbRead,
			expected: "",
		},
		{
			name:     "invalid verb",
			resource: ResourceRepositories,
			verb:     RbacVerbAny,
			expected: "",
		},
		{
			name:     "undefined verb",
			resource: ResourceRepositories,
			verb:     RbacVerbUndefined,
			expected: "",
		},
		{
			name:     "templates upload (invalid combination)",
			resource: ResourceTemplates,
			verb:     RbacVerbUpload,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapToKesselPermission(tt.resource, tt.verb)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildSubjectReference(t *testing.T) {
	tests := []struct {
		name     string
		identity identity.XRHID
		expected string
	}{
		{
			name: "user identity",
			identity: identity.XRHID{
				Identity: identity.Identity{
					Type: "User",
					User: &identity.User{
						UserID: "user123",
					},
				},
			},
			expected: "redhat/user123",
		},
		{
			name: "service account identity",
			identity: identity.XRHID{
				Identity: identity.Identity{
					Type: "ServiceAccount",
					ServiceAccount: &identity.ServiceAccount{
						UserId: "sa456",
					},
				},
			},
			expected: "redhat/sa456",
		},
		{
			name: "unknown identity type",
			identity: identity.XRHID{
				Identity: identity.Identity{
					Type: "Unknown",
				},
			},
			expected: "redhat/",
		},
	}

	// Create a minimal wrapper for testing
	wrapper := &KesselClientWrapper{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := identity.WithIdentity(context.Background(), tt.identity)
			result := wrapper.buildSubjectReference(ctx)

			assert.NotNil(t, result)
			assert.NotNil(t, result.Resource)
			assert.Equal(t, "principal", result.Resource.ResourceType)
			assert.Equal(t, tt.expected, result.Resource.ResourceId)
			assert.NotNil(t, result.Resource.Reporter)
			assert.Equal(t, "rbac", result.Resource.Reporter.Type)
		})
	}
}

func TestGetRootWorkspaceID(t *testing.T) {
	tests := []struct {
		name           string
		rbacUrl        string
		mockResponse   interface{}
		mockStatusCode int
		orgID          string
		expectError    bool
		errorContains  string
		expectedID     string
	}{
		{
			name:           "success single workspace",
			rbacUrl:        "", // Will be set by test server
			mockStatusCode: http.StatusOK,
			mockResponse: workspaceResponse{
				Data: []workspace{
					{ID: "workspace-123"},
				},
			},
			orgID:       "org123",
			expectError: false,
			expectedID:  "workspace-123",
		},
		{
			name:           "error no workspaces",
			rbacUrl:        "",
			mockStatusCode: http.StatusOK,
			mockResponse: workspaceResponse{
				Data: []workspace{},
			},
			orgID:         "org123",
			expectError:   true,
			errorContains: "unexpected number of root workspaces: 0",
		},
		{
			name:           "error multiple workspaces",
			rbacUrl:        "",
			mockStatusCode: http.StatusOK,
			mockResponse: workspaceResponse{
				Data: []workspace{
					{ID: "workspace-1"},
					{ID: "workspace-2"},
				},
			},
			orgID:         "org123",
			expectError:   true,
			errorContains: "unexpected number of root workspaces: 2",
		},
		{
			name:           "http error",
			rbacUrl:        "",
			mockStatusCode: http.StatusInternalServerError,
			mockResponse:   "Internal Server Error",
			orgID:          "org123",
			expectError:    true,
			errorContains:  "unexpected status code: 500",
		},
		{
			name:          "missing rbac url",
			rbacUrl:       "",
			orgID:         "org123",
			expectError:   true,
			errorContains: "RBAC URL not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			wrapper := &KesselClientWrapper{}

			if tt.name != "missing rbac url" {
				// Create mock server
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify request headers
					assert.Equal(t, tt.orgID, r.Header.Get("x-rh-rbac-org-id"))
					assert.Contains(t, r.URL.Path, "/api/rbac/v2/workspaces/")
					assert.Equal(t, "root", r.URL.Query().Get("type"))

					w.WriteHeader(tt.mockStatusCode)
					if tt.mockStatusCode == http.StatusOK {
						json.NewEncoder(w).Encode(tt.mockResponse)
					} else {
						w.Write([]byte(tt.mockResponse.(string)))
					}
				}))
				defer server.Close()
				wrapper.rbacUrl = server.URL
			}

			// Create context with identity
			testIdentity := &identity.XRHID{
				Identity: identity.Identity{
					Internal: identity.Internal{
						OrgID: tt.orgID,
					},
				},
			}
			ctx := identity.WithIdentity(context.Background(), *testIdentity)

			// Call function
			result, err := wrapper.getRootWorkspaceID(ctx)

			// Verify results
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, result)
			}
		})
	}
}

func TestGetRootWorkspaceID_InvalidJSON(t *testing.T) {
	// Test invalid JSON response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	wrapper := &KesselClientWrapper{
		rbacUrl: server.URL,
	}

	testIdentity := &identity.XRHID{
		Identity: identity.Identity{
			Internal: identity.Internal{
				OrgID: "org123",
			},
		},
	}
	ctx := identity.WithIdentity(context.Background(), *testIdentity)

	result, err := wrapper.getRootWorkspaceID(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error unmarshalling response")
	assert.Empty(t, result)
}

// Mock test for Allowed function - this would require more complex mocking
// of the Kessel client, which is beyond the scope of basic unit tests
func TestAllowed_PermissionMapping(t *testing.T) {
	// Test that the permission mapping works correctly within the Allowed function
	wrapper := &KesselClientWrapper{
		rbacUrl: "", // This will cause getRootWorkspaceID to fail, which is expected
	}

	testIdentity := &identity.XRHID{
		Identity: identity.Identity{
			Type: "User",
			User: &identity.User{
				UserID: "user123",
			},
			Internal: identity.Internal{
				OrgID: "org123",
			},
		},
	}
	ctx := identity.WithIdentity(context.Background(), *testIdentity)

	// Test invalid resource/verb mapping
	allowed, err := wrapper.Allowed(ctx, ResourceAny, RbacVerbRead)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no permission mapping")
	assert.False(t, allowed)
}

func TestKesselClientWrapper_Interface(t *testing.T) {
	// Verify that KesselClientWrapper implements ClientWrapper interface
	var _ ClientWrapper = (*KesselClientWrapper)(nil)
}

// Benchmark tests
func BenchmarkMapToKesselPermission(b *testing.B) {
	for i := 0; i < b.N; i++ {
		mapToKesselPermission(ResourceRepositories, RbacVerbRead)
	}
}

func BenchmarkBuildSubjectReference(b *testing.B) {
	wrapper := &KesselClientWrapper{}
	testIdentity := &identity.XRHID{
		Identity: identity.Identity{
			Type: "User",
			User: &identity.User{
				UserID: "user123",
			},
		},
	}
	ctx := identity.WithIdentity(context.Background(), *testIdentity)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wrapper.buildSubjectReference(ctx)
	}
}
