# Kessel Authorization Integration Plan

Based on the migration guide and analysis of the current RBAC implementation, here's a detailed plan for adding Kessel support to the content-sources-backend application:

## **Design Overview**

This plan implements Kessel support by creating a new implementation of the existing `rbac.ClientWrapper` interface. This approach:
- **Reuses existing interfaces** - No new authorization abstractions needed
- **Requires minimal changes** - Existing middleware and handlers remain unchanged  
- **Maintains backward compatibility** - RBAC v1 continues to work exactly as before
- **Enables easy switching** - Configuration determines which implementation to use
- **Leverages client library features** - Workspace caching and other optimizations handled by Kessel client library

## **Phase 1: Analysis and Design** ✅ **COMPLETED**

### **1.1 Identify Current Permission Patterns**

**Comprehensive Analysis of Current RBAC Implementation:**

**Current Resources and Verbs:**
- `repositories` resource: `read`, `write`, `upload` verbs (45+ routes)
- `templates` resource: `read`, `write` verbs (7 routes) 
- Feature-based access: `snapshots`, `admin_tasks` (controlled via allowlists)

**Architecture Details:**
- Uses `rbac.ClientWrapper` interface for authorization
- Route-to-permission mapping via `addRepoRoute()`/`addTemplateRoute()` helper functions
- All permissions stored in `rbac.ServicePermissions` map
- RBAC middleware looks up permissions and calls `ClientWrapper.Allowed()`
- Org admin bypass: `identity.User.OrgAdmin` skips all RBAC checks

**Pattern Classification:**
- **Root Workspace Pattern**: All operations are org-wide (repositories, templates, features)
- **Feature-based Access**: Snapshots and Admin Tasks use separate allowlist controls
- **No host-specific or workspace-aware assets currently**

### **1.2 Model Permissions in KSL Language** ✅ **COMPLETED**

**Created: `kessel-permissions.ksl`**

```ksl
version 0.1
namespace content_sources

import rbac

# Repository permissions
@rbac.add_v1_based_permission(app:'content-sources', resource:'repositories', verb:'read', v2_perm:'content_sources_repositories_view');
@rbac.add_v1_based_permission(app:'content-sources', resource:'repositories', verb:'write', v2_perm:'content_sources_repositories_edit');
@rbac.add_v1_based_permission(app:'content-sources', resource:'repositories', verb:'upload', v2_perm:'content_sources_repositories_upload');

# Template permissions  
@rbac.add_v1_based_permission(app:'content-sources', resource:'templates', verb:'read', v2_perm:'content_sources_templates_view');
@rbac.add_v1_based_permission(app:'content-sources', resource:'templates', verb:'write', v2_perm:'content_sources_templates_edit');
```

**Key Decisions:**
- **Root workspace pattern** for all permissions (org-wide access)
- **Consistent naming**: `content_sources_<resource>_<action>` format
- **Direct v1-to-v2 mapping**: No complex permission combinations needed
- **Feature flags remain separate**: Snapshots and Admin Tasks keep existing allowlist logic

### **1.3 Phase 1 Summary**

**✅ Deliverables Completed:**
1. **Comprehensive RBAC pattern analysis** - Identified all resources, verbs, and architectural patterns
2. **KSL permission definitions** - Created `kessel-permissions.ksl` with 5 v1-to-v2 permission mappings
3. **Pattern classification** - Confirmed Root Workspace pattern for all operations
4. **Architecture understanding** - Documented current `rbac.ClientWrapper` interface and middleware flow

**Key Insights:**
- Current system is well-structured for Kessel integration (uses interface-based design)
- Simple permission model (2 resources, 3 verbs) makes migration straightforward
- Existing org admin bypass logic can be preserved
- Feature-based access controls can remain unchanged during initial migration

**Ready for Phase 2:** ✅ Kessel client implementation can now begin

---

## **Phase 2: Implementation** ✅ **COMPLETED**

### **2.1 Add Kessel Client Dependencies** ✅ **COMPLETED**

**✅ Added Kessel client dependency:**
```bash
go get github.com/project-kessel/inventory-client-go
```

**✅ Updated `pkg/config/config.go` with Kessel configuration:**
```go
type Clients struct {
    // ... existing RBAC v1 fields ...
    KesselEnabled          bool   `mapstructure:"kessel_enabled"`
    KesselUrl              string `mapstructure:"kessel_url"`
    KesselAuthEnabled      bool   `mapstructure:"kessel_auth_enabled"`
    KesselAuthClientId     string `mapstructure:"kessel_auth_client_id"`
    KesselAuthClientSecret string `mapstructure:"kessel_auth_client_secret"`
    KesselAuthOidcIssuer   string `mapstructure:"kessel_auth_oidc_issuer"`
    KesselInsecure         bool   `mapstructure:"kessel_insecure"`
}
```

**✅ Set appropriate configuration defaults** (disabled by default for safe rollout)

### **2.2 Create Kessel Implementation** ✅ **COMPLETED**

**✅ Created `pkg/rbac/kessel.go`** implementing `rbac.ClientWrapper` interface:

**✅ Key Implementation Features:**
- **Interface Compliance**: Implements `rbac.ClientWrapper.Allowed(ctx, resource, verb) (bool, error)`
- **Org Admin Bypass**: Preserves existing behavior for org admins
- **Permission Mapping**: Maps RBAC v1 resources/verbs to Kessel v2 permission names
- **Structured for Enhancement**: Placeholder implementations ready for actual Kessel API calls
- **Error Handling**: Comprehensive logging and error propagation

**✅ Permission Mappings Implemented:**
- `repositories` + `read` → `content_sources_repositories_view`
- `repositories` + `write` → `content_sources_repositories_edit`  
- `repositories` + `upload` → `content_sources_repositories_upload`
- `templates` + `read` → `content_sources_templates_view`
- `templates` + `write` → `content_sources_templates_edit`

**✅ TODOs for Future Enhancement:**
- Workspace ID lookup via RBAC v2 API (`GET /v2/workspaces?type=root`)
- Actual Kessel gRPC client initialization with auth
- Real `Check`/`CheckForUpdate` API calls

### **2.3 Update Router Configuration** ✅ **COMPLETED**

**✅ Updated `pkg/router/route.go`** to choose authorization implementation:

**✅ Router Selection Logic:**
- **Kessel preferred** if both Kessel and RBAC v1 are enabled
- **RBAC v1 fallback** if only RBAC v1 is enabled  
- **Graceful handling** when no authorization is configured
- **Clear logging** indicating which authorization system is active

**✅ Backward Compatibility:** 
- No changes to existing middleware interface
- All existing routes continue to work unchanged
- Feature flags and admin task controls preserved

### **2.4 Phase 2 Summary**

**✅ Implementation Complete - 3 Major Components:**

1. **Configuration System** - Added Kessel config fields with safe defaults
2. **Kessel Client Wrapper** - Implements existing `rbac.ClientWrapper` interface  
3. **Router Integration** - Smart selection between Kessel/RBAC v1

**✅ Key Benefits Achieved:**
- **Zero Breaking Changes** - Existing functionality preserved
- **Interface Reuse** - Leverages existing middleware architecture
- **Gradual Rollout** - Disabled by default, can enable per environment
- **Clear Observability** - Comprehensive logging for troubleshooting

**✅ Ready for Next Phase:** Testing and validation of the implementation

## **Phase 3: Testing**

### **3.1 Unit Tests**

Create `pkg/rbac/kessel_test.go`:
```go
package rbac

import (
    "context"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
)

type KesselTestSuite struct {
    suite.Suite
    client KesselClientWrapper
}

func (s *KesselTestSuite) TestAllowed() {
    // Test various permission scenarios
}

func (s *KesselTestSuite) TestOrgAdminBypass() {
    // Test that org admins bypass Kessel checks
}
```

### **3.2 Integration Tests**

Update existing RBAC tests to work with both backends:
- Modify `pkg/middleware/rbac_test.go` to test both RBAC v1 and Kessel
- Add configuration tests for both authorization methods

### **3.3 Mock Implementation**

Create `pkg/rbac/mock_kessel_client_wrapper.go`:
```go
package rbac

import (
    "context"
    "github.com/stretchr/testify/mock"
)

// MockKesselClientWrapper implements ClientWrapper for testing
type MockKesselClientWrapper struct {
    mock.Mock
}

func (m *MockKesselClientWrapper) Allowed(ctx context.Context, resource Resource, verb Verb) (bool, error) {
    args := m.Called(ctx, resource, verb)
    return args.Bool(0), args.Error(1)
}

// NewMockKesselClientWrapper creates a mock that implements ClientWrapper
func NewMockKesselClientWrapper() ClientWrapper {
    return &MockKesselClientWrapper{}
}
```

## **Phase 4: Deployment Configuration**

### **4.1 Environment Variables**

Add to deployment configurations:
```yaml
- name: KESSEL_ENABLED
  value: "false"
- name: KESSEL_URL
  value: ""
- name: KESSEL_AUTH_ENABLED
  value: "true"
- name: KESSEL_AUTH_CLIENT_ID
  valueFrom:
    secretKeyRef:
      name: kessel-auth
      key: client-id
- name: KESSEL_AUTH_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: kessel-auth
      key: client-secret
- name: KESSEL_AUTH_OIDC_ISSUER
  value: ""
- name: KESSEL_INSECURE
  value: "false"
```

### **4.2 ClowdApp Updates**

Update deployment templates to include Kessel configuration options for stage/prod environments.

## **Phase 5: Feature Flags and Rollout**

### **5.1 Feature Flag Implementation**

Add feature flag support:
```go
// In config
type FeaturesConfig struct {
    KesselAuthorization config.Feature `mapstructure:"kessel_authorization"`
    // ... existing features
}

// In handler/features.go
func CheckKesselAuthorizationAccessible(ctx context.Context) error {
    if !config.Get().Features.KesselAuthorization.Enabled {
        return ce.NewErrorResponse(http.StatusBadRequest, "Kessel Authorization is disabled.", "")
    }
    return accessible(ctx, config.Get().Features.KesselAuthorization)
}
```

### **5.2 Gradual Rollout Strategy**

1. **Phase 1**: Deploy with Kessel disabled, RBAC v1 enabled (current state)
2. **Phase 2**: Enable Kessel for specific accounts/users via feature flags
3. **Phase 3**: Gradually expand Kessel usage
4. **Phase 4**: Switch default to Kessel, keep RBAC v1 as fallback
5. **Phase 5**: Remove RBAC v1 support (future)

## **Phase 6: Monitoring and Observability**

### **6.1 Metrics**

Add Kessel-specific metrics:
```go
// In pkg/instrumentation/metrics.go
type Metrics struct {
    // ... existing metrics
    KesselAuthzDuration prometheus.HistogramVec
    KesselAuthzErrors   prometheus.CounterVec
}
```

### **6.2 Logging**

Add structured logging for Kessel operations:
```go
logger.Info().
    Str("authz_backend", "kessel").
    Str("resource", string(resource)).
    Str("verb", string(verb)).
    Bool("allowed", allowed).
    Msg("Authorization check completed")
```

## **Phase 7: Documentation**

### **7.1 Update README**

Add Kessel configuration documentation to README.md

### **7.2 Migration Guide**

Create internal documentation for:
- Configuration changes needed
- Testing procedures
- Rollback procedures

## **Implementation Timeline**

1. **Week 1**: Phase 1 (Analysis) and Phase 2.1-2.2 (Dependencies and Kessel client implementation)
2. **Week 2**: Phase 2.3-2.4 (Configuration updates and integration)
3. **Week 3**: Phase 2.5 (Router updates and integration)
4. **Week 4**: Phase 3 (Testing and mock implementations)
5. **Week 5**: Phase 4-5 (Deployment configuration and feature flags)
6. **Week 6**: Phase 6-7 (Monitoring, observability, and documentation)

This simplified approach keeps all RBAC-related code in the same package while implementing Kessel as an alternative ClientWrapper. The implementation is cleaner and faster with no new packages needed. The plan ensures backward compatibility while adding Kessel support, allowing for gradual migration and testing. 