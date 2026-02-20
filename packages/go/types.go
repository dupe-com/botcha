package botcha

// ==================== Challenge Types ====================

// Problem represents a single challenge problem.
type Problem struct {
	Num       int    `json:"num"`
	Operation string `json:"operation,omitempty"`
}

// Challenge represents a BOTCHA speed challenge.
type Challenge struct {
	ID           string    `json:"id"`
	Problems     []Problem `json:"problems"`
	TimeLimit    int       `json:"timeLimit"`
	Instructions string    `json:"instructions"`
}

// ChallengeResponse is returned by GET /v1/token.
type ChallengeResponse struct {
	Success   bool      `json:"success"`
	Challenge Challenge `json:"challenge"`
}

// VerifyRequest is sent to POST /v1/token/verify.
type VerifyRequest struct {
	ID       string   `json:"id"`
	Answers  []string `json:"answers"`
	AppID    string   `json:"app_id,omitempty"`
	Audience string   `json:"audience,omitempty"`
}

// TokenResponse is returned by POST /v1/token/verify.
type TokenResponse struct {
	Success      bool   `json:"success"`
	Verified     bool   `json:"verified"`
	Token        string `json:"token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// ==================== Token Management Types ====================

// ValidateTokenRequest is sent to POST /v1/token/validate.
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse is returned by POST /v1/token/validate.
type ValidateTokenResponse struct {
	Success bool   `json:"success"`
	Valid   bool   `json:"valid"`
	AppID   string `json:"app_id"`
	AgentID string `json:"agent_id"`
	Sub     string `json:"sub"`
	Exp     int64  `json:"exp"`
	Iat     int64  `json:"iat"`
	Error   string `json:"error,omitempty"`
}

// RevokeTokenRequest is sent to POST /v1/token/revoke.
type RevokeTokenRequest struct {
	Token string `json:"token"`
	AppID string `json:"app_id,omitempty"`
}

// RevokeTokenResponse is returned by POST /v1/token/revoke.
type RevokeTokenResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RefreshTokenRequest is sent to POST /v1/token/refresh.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	AppID        string `json:"app_id,omitempty"`
}

// ==================== App Management Types ====================

// CreateAppResponse is returned by POST /v1/apps.
type CreateAppResponse struct {
	Success              bool   `json:"success"`
	AppID                string `json:"app_id"`
	Name                 string `json:"name"`
	AppSecret            string `json:"app_secret"`
	Email                string `json:"email"`
	EmailVerified        bool   `json:"email_verified"`
	VerificationRequired bool   `json:"verification_required"`
	Warning              string `json:"warning"`
	CredentialAdvice     string `json:"credential_advice"`
	CreatedAt            string `json:"created_at"`
	RateLimit            int    `json:"rate_limit"`
	NextStep             string `json:"next_step"`
}

// VerifyEmailResponse is returned by POST /v1/apps/:id/verify-email.
type VerifyEmailResponse struct {
	Success       bool   `json:"success"`
	EmailVerified bool   `json:"email_verified"`
	Error         string `json:"error,omitempty"`
	Message       string `json:"message,omitempty"`
}

// ResendVerificationResponse is returned by POST /v1/apps/:id/resend-verification.
type ResendVerificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RotateSecretResponse is returned by POST /v1/apps/:id/rotate-secret.
type RotateSecretResponse struct {
	Success   bool   `json:"success"`
	AppID     string `json:"app_id,omitempty"`
	AppSecret string `json:"app_secret,omitempty"`
	Warning   string `json:"warning,omitempty"`
	RotatedAt string `json:"rotated_at,omitempty"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

// ==================== Agent Registry Types ====================

// RegisterAgentInput is the request body for POST /v1/agents.
type RegisterAgentInput struct {
	Name     string `json:"name"`
	Operator string `json:"operator,omitempty"`
	Version  string `json:"version,omitempty"`
}

// AgentResponse is returned by agent endpoints.
type AgentResponse struct {
	Success    bool   `json:"success"`
	AgentID    string `json:"agent_id"`
	AppID      string `json:"app_id"`
	Name       string `json:"name"`
	Operator   string `json:"operator,omitempty"`
	Version    string `json:"version,omitempty"`
	CreatedAt  string `json:"created_at"`
	TapEnabled bool   `json:"tap_enabled"`
}

// AgentListResponse is returned by GET /v1/agents.
type AgentListResponse struct {
	Success bool            `json:"success"`
	Agents  []AgentResponse `json:"agents"`
	Count   int             `json:"count"`
}

// ==================== TAP (Trusted Agent Protocol) Types ====================

// TAPAction represents allowed TAP actions.
type TAPAction = string

// TAPTrustLevel represents the trust level of a TAP agent.
type TAPTrustLevel = string

// TAPSignatureAlgorithm represents supported signing algorithms.
type TAPSignatureAlgorithm = string

// TAPCapability represents a TAP capability with scope and restrictions.
type TAPCapability struct {
	Action       TAPAction      `json:"action"`
	Scope        []string       `json:"scope,omitempty"`
	Restrictions map[string]any `json:"restrictions,omitempty"`
}

// TAPIntent represents the intent of a TAP session.
type TAPIntent struct {
	Action   TAPAction `json:"action"`
	Resource string    `json:"resource,omitempty"`
	Scope    []string  `json:"scope,omitempty"`
	Duration int       `json:"duration,omitempty"`
}

// RegisterTAPAgentInput is the request body for TAP agent registration.
type RegisterTAPAgentInput struct {
	Name               string          `json:"name"`
	Operator           string          `json:"operator,omitempty"`
	Version            string          `json:"version,omitempty"`
	PublicKey          string          `json:"public_key,omitempty"`
	SignatureAlgorithm string          `json:"signature_algorithm,omitempty"`
	Capabilities       []TAPCapability `json:"capabilities,omitempty"`
	TrustLevel         string          `json:"trust_level,omitempty"`
	Issuer             string          `json:"issuer,omitempty"`
	KeyExpiresAt       string          `json:"key_expires_at,omitempty"`
}

// TAPAgentResponse is returned by TAP agent endpoints.
type TAPAgentResponse struct {
	Success            bool            `json:"success"`
	AgentID            string          `json:"agent_id"`
	AppID              string          `json:"app_id"`
	Name               string          `json:"name"`
	Operator           string          `json:"operator,omitempty"`
	Version            string          `json:"version,omitempty"`
	CreatedAt          string          `json:"created_at"`
	TapEnabled         bool            `json:"tap_enabled"`
	TrustLevel         string          `json:"trust_level,omitempty"`
	Capabilities       []TAPCapability `json:"capabilities,omitempty"`
	SignatureAlgorithm string          `json:"signature_algorithm,omitempty"`
	Issuer             string          `json:"issuer,omitempty"`
	HasPublicKey       bool            `json:"has_public_key"`
	KeyFingerprint     string          `json:"key_fingerprint,omitempty"`
	LastVerifiedAt     *string         `json:"last_verified_at"`
	KeyExpiresAt       *string         `json:"key_expires_at"`
	PublicKey          string          `json:"public_key,omitempty"`
}

// TAPAgentListResponse is returned by GET /v1/agents/tap.
type TAPAgentListResponse struct {
	Success         bool               `json:"success"`
	Agents          []TAPAgentResponse `json:"agents"`
	Count           int                `json:"count"`
	TapEnabledCount int                `json:"tap_enabled_count"`
}

// CreateTAPSessionInput is the request body for POST /v1/sessions/tap.
type CreateTAPSessionInput struct {
	AgentID     string    `json:"agent_id"`
	UserContext string    `json:"user_context"`
	Intent      TAPIntent `json:"intent"`
}

// TAPSessionResponse is returned by TAP session endpoints.
type TAPSessionResponse struct {
	Success       bool            `json:"success"`
	SessionID     string          `json:"session_id"`
	AgentID       string          `json:"agent_id"`
	AppID         string          `json:"app_id,omitempty"`
	Capabilities  []TAPCapability `json:"capabilities,omitempty"`
	Intent        TAPIntent       `json:"intent"`
	CreatedAt     string          `json:"created_at,omitempty"`
	ExpiresAt     string          `json:"expires_at"`
	TimeRemaining int             `json:"time_remaining,omitempty"`
}

// ==================== JWK Types ====================

// JWK represents a JSON Web Key.
type JWK struct {
	Kty       string `json:"kty"`
	Kid       string `json:"kid"`
	Use       string `json:"use"`
	Alg       string `json:"alg"`
	N         string `json:"n,omitempty"`
	E         string `json:"e,omitempty"`
	Crv       string `json:"crv,omitempty"`
	X         string `json:"x,omitempty"`
	Y         string `json:"y,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// JWKSet represents a set of JSON Web Keys.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// ==================== Delegation Types ====================

// CreateDelegationInput is the request body for POST /v1/delegations.
type CreateDelegationInput struct {
	GrantorID          string            `json:"grantor_id"`
	GranteeID          string            `json:"grantee_id"`
	Capabilities       []TAPCapability   `json:"capabilities"`
	DurationSeconds    int               `json:"duration_seconds,omitempty"`
	MaxDepth           int               `json:"max_depth,omitempty"`
	ParentDelegationID string            `json:"parent_delegation_id,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// DelegationResponse is returned by delegation endpoints.
type DelegationResponse struct {
	Success            bool              `json:"success"`
	DelegationID       string            `json:"delegation_id"`
	GrantorID          string            `json:"grantor_id"`
	GranteeID          string            `json:"grantee_id"`
	AppID              string            `json:"app_id"`
	Capabilities       []TAPCapability   `json:"capabilities"`
	Chain              []string          `json:"chain"`
	Depth              int               `json:"depth"`
	MaxDepth           int               `json:"max_depth"`
	ParentDelegationID *string           `json:"parent_delegation_id"`
	CreatedAt          string            `json:"created_at"`
	ExpiresAt          string            `json:"expires_at"`
	Revoked            bool              `json:"revoked,omitempty"`
	RevokedAt          *string           `json:"revoked_at"`
	RevocationReason   *string           `json:"revocation_reason"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	TimeRemaining      int               `json:"time_remaining,omitempty"`
}

// DelegationListEntry is a single entry in a delegation list.
type DelegationListEntry struct {
	DelegationID       string          `json:"delegation_id"`
	GrantorID          string          `json:"grantor_id"`
	GranteeID          string          `json:"grantee_id"`
	Capabilities       []TAPCapability `json:"capabilities"`
	Chain              []string        `json:"chain"`
	Depth              int             `json:"depth"`
	CreatedAt          string          `json:"created_at"`
	ExpiresAt          string          `json:"expires_at"`
	Revoked            bool            `json:"revoked"`
	ParentDelegationID *string         `json:"parent_delegation_id"`
}

// DelegationListResponse is returned by GET /v1/delegations.
type DelegationListResponse struct {
	Success     bool                  `json:"success"`
	Delegations []DelegationListEntry `json:"delegations"`
	Count       int                   `json:"count"`
	AgentID     string                `json:"agent_id"`
	Direction   string                `json:"direction"`
}

// RevokeDelegationResponse is returned by POST /v1/delegations/:id/revoke.
type RevokeDelegationResponse struct {
	Success          bool    `json:"success"`
	DelegationID     string  `json:"delegation_id"`
	Revoked          bool    `json:"revoked"`
	RevokedAt        *string `json:"revoked_at"`
	RevocationReason *string `json:"revocation_reason"`
	Message          string  `json:"message"`
}

// DelegationVerifyResponse is returned by POST /v1/verify/delegation.
type DelegationVerifyResponse struct {
	Success               bool                  `json:"success"`
	Valid                 bool                  `json:"valid"`
	ChainLength           int                   `json:"chain_length,omitempty"`
	Chain                 []DelegationChainItem `json:"chain,omitempty"`
	EffectiveCapabilities []TAPCapability       `json:"effective_capabilities,omitempty"`
	Error                 string                `json:"error,omitempty"`
}

// DelegationChainItem is a single item in a delegation chain.
type DelegationChainItem struct {
	DelegationID string          `json:"delegation_id"`
	GrantorID    string          `json:"grantor_id"`
	GranteeID    string          `json:"grantee_id"`
	Capabilities []TAPCapability `json:"capabilities"`
	Depth        int             `json:"depth"`
	CreatedAt    string          `json:"created_at"`
	ExpiresAt    string          `json:"expires_at"`
}

// ==================== Attestation Types ====================

// IssueAttestationInput is the request body for POST /v1/attestations.
type IssueAttestationInput struct {
	AgentID         string            `json:"agent_id"`
	Can             []string          `json:"can"`
	Cannot          []string          `json:"cannot,omitempty"`
	Restrictions    map[string]any    `json:"restrictions,omitempty"`
	DurationSeconds int               `json:"duration_seconds,omitempty"`
	DelegationID    string            `json:"delegation_id,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// AttestationResponse is returned by attestation endpoints.
type AttestationResponse struct {
	Success          bool              `json:"success"`
	AttestationID    string            `json:"attestation_id"`
	AgentID          string            `json:"agent_id"`
	AppID            string            `json:"app_id"`
	Token            string            `json:"token"`
	Can              []string          `json:"can"`
	Cannot           []string          `json:"cannot"`
	Restrictions     map[string]any    `json:"restrictions,omitempty"`
	DelegationID     *string           `json:"delegation_id"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	CreatedAt        string            `json:"created_at"`
	ExpiresAt        string            `json:"expires_at"`
	Revoked          bool              `json:"revoked,omitempty"`
	RevokedAt        *string           `json:"revoked_at"`
	RevocationReason *string           `json:"revocation_reason"`
	TimeRemaining    int               `json:"time_remaining,omitempty"`
}

// AttestationListEntry is a single entry in an attestation list.
type AttestationListEntry struct {
	AttestationID string   `json:"attestation_id"`
	AgentID       string   `json:"agent_id"`
	Can           []string `json:"can"`
	Cannot        []string `json:"cannot"`
	CreatedAt     string   `json:"created_at"`
	ExpiresAt     string   `json:"expires_at"`
	Revoked       bool     `json:"revoked"`
	DelegationID  *string  `json:"delegation_id"`
}

// AttestationListResponse is returned by GET /v1/attestations.
type AttestationListResponse struct {
	Success      bool                   `json:"success"`
	Attestations []AttestationListEntry `json:"attestations"`
	Count        int                    `json:"count"`
	AgentID      string                 `json:"agent_id"`
}

// RevokeAttestationResponse is returned by POST /v1/attestations/:id/revoke.
type RevokeAttestationResponse struct {
	Success          bool    `json:"success"`
	AttestationID    string  `json:"attestation_id"`
	Revoked          bool    `json:"revoked"`
	RevokedAt        *string `json:"revoked_at"`
	RevocationReason *string `json:"revocation_reason"`
	Message          string  `json:"message"`
}

// AttestationVerifyResponse is returned by POST /v1/verify/attestation.
type AttestationVerifyResponse struct {
	Success           bool           `json:"success"`
	Valid             bool           `json:"valid"`
	Allowed           bool           `json:"allowed,omitempty"`
	AgentID           *string        `json:"agent_id"`
	Issuer            string         `json:"issuer,omitempty"`
	Can               []string       `json:"can,omitempty"`
	Cannot            []string       `json:"cannot,omitempty"`
	Restrictions      map[string]any `json:"restrictions,omitempty"`
	DelegationID      *string        `json:"delegation_id"`
	IssuedAt          string         `json:"issued_at,omitempty"`
	ExpiresAt         string         `json:"expires_at,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	MatchedRule       *string        `json:"matched_rule"`
	CheckedCapability string         `json:"checked_capability,omitempty"`
	Error             string         `json:"error,omitempty"`
}

// ==================== Reputation Types ====================

// ReputationTier represents an agent's reputation tier.
type ReputationTier = string

// ReputationEventCategory represents the category of a reputation event.
type ReputationEventCategory = string

// ReputationEventAction represents a specific reputation event action.
type ReputationEventAction = string

// ReputationScoreResponse is returned by GET /v1/reputation/:agentId.
type ReputationScoreResponse struct {
	Success        bool               `json:"success"`
	AgentID        string             `json:"agent_id"`
	AppID          string             `json:"app_id"`
	Score          float64            `json:"score"`
	Tier           ReputationTier     `json:"tier"`
	EventCount     int                `json:"event_count"`
	PositiveEvents int                `json:"positive_events"`
	NegativeEvents int                `json:"negative_events"`
	LastEventAt    *string            `json:"last_event_at"`
	CreatedAt      string             `json:"created_at"`
	UpdatedAt      string             `json:"updated_at"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

// RecordReputationEventInput is the request body for POST /v1/reputation/events.
type RecordReputationEventInput struct {
	AgentID       string            `json:"agent_id"`
	Category      string            `json:"category"`
	Action        string            `json:"action"`
	SourceAgentID string            `json:"source_agent_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ReputationEvent represents a single reputation event.
type ReputationEvent struct {
	EventID       string            `json:"event_id"`
	AgentID       string            `json:"agent_id"`
	Category      string            `json:"category"`
	Action        string            `json:"action"`
	Delta         float64           `json:"delta"`
	ScoreBefore   float64           `json:"score_before"`
	ScoreAfter    float64           `json:"score_after"`
	SourceAgentID *string           `json:"source_agent_id"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     string            `json:"created_at"`
}

// ReputationEventResponse is returned by POST /v1/reputation/events.
type ReputationEventResponse struct {
	Success bool            `json:"success"`
	Event   ReputationEvent `json:"event"`
	Score   struct {
		Score      float64        `json:"score"`
		Tier       ReputationTier `json:"tier"`
		EventCount int            `json:"event_count"`
	} `json:"score"`
}

// ReputationEventListResponse is returned by GET /v1/reputation/:agentId/events.
type ReputationEventListResponse struct {
	Success bool              `json:"success"`
	Events  []ReputationEvent `json:"events"`
	Count   int               `json:"count"`
	AgentID string            `json:"agent_id"`
}

// ReputationResetResponse is returned by POST /v1/reputation/:agentId/reset.
type ReputationResetResponse struct {
	Success bool           `json:"success"`
	AgentID string         `json:"agent_id"`
	Score   float64        `json:"score"`
	Tier    ReputationTier `json:"tier"`
	Message string         `json:"message"`
}
