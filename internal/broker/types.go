package broker

import (
	"context"

	"github.com/QuBiit0/qbit-vault/internal/refusal"
)

// Envelope is the part every request carries (CONTRACT.md § Envelope).
type Envelope struct {
	Contract string `json:"contract"`
	Op       string `json:"op"`
	V        int    `json:"v"`
	Session  string `json:"session"`
	Cwd      string `json:"cwd"`
	Host     *Host  `json:"host,omitempty"`
}

// Host names the calling host, for audit.
type Host struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ExecSecret injects vault secret From (default Name) as variable Name.
type ExecSecret struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
}

// ExecRequest is a validated `exec`, defaults applied.
type ExecRequest struct {
	Command   string
	Secrets   []ExecSecret
	TimeoutMS int
	Shell     string
}

// GrantRequest is a validated `grant`. Layer is "global" or "project".
type GrantRequest struct {
	Name        string
	Layer       string
	Scope       string
	TTLMS       int
	PromptToken string
}

// RevokeRequest is a validated `revoke`: exactly one target is set.
type RevokeRequest struct {
	Name        string
	All         bool
	SessionOnly bool
}

// Field is one box of a `request`.
type Field struct {
	Name        string `json:"name"`
	Kind        string `json:"kind,omitempty"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
}

// RequestRequest is a validated `request`; Fields always holds at least one
// entry (a single `name` becomes one secret field). Single reports the
// single-`name` form, whose response also carries `ref` and `layer`.
type RequestRequest struct {
	Fields         []Field
	Single         bool
	Reason         string
	SuggestedScope string
	SuggestedLayer string
}

// ManageChanges are the metadata fields an `edit` may change; nil means
// unchanged.
type ManageChanges struct {
	Description *string   `json:"description,omitempty"`
	Binaries    *[]string `json:"binaries,omitempty"`
	Hosts       *[]string `json:"hosts,omitempty"`
	Sensitive   *bool     `json:"sensitive,omitempty"`
}

// ManageRequest is a validated `manage`.
type ManageRequest struct {
	Action  string
	Name    string
	Layer   string
	Reason  string
	To      string
	Changes *ManageChanges
}

// GrantInfo is a grant as the model sees it.
type GrantInfo struct {
	Scope     string  `json:"scope"`
	ExpiresAt *string `json:"expires_at"`
}

// Project is the repository of the envelope's cwd.
type Project struct {
	Root  string `json:"root"`
	Label string `json:"label"`
}

// SecretMeta is one listed secret: never a value.
type SecretMeta struct {
	Name            string     `json:"name"`
	Layer           string     `json:"layer"`
	OverridesGlobal bool       `json:"overrides_global"`
	Kind            string     `json:"kind"`
	Description     string     `json:"description"`
	Sensitive       bool       `json:"sensitive"`
	Binaries        []string   `json:"binaries"`
	Hosts           []string   `json:"hosts"`
	CreatedAt       string     `json:"created_at"`
	UpdatedAt       string     `json:"updated_at"`
	Grant           *GrantInfo `json:"grant"`
}

// Cooldown is a name the agent may not ask for again until Until.
type Cooldown struct {
	Name  string `json:"name"`
	Until string `json:"until"`
}

// ListResult is what a backend reports for `list`; the broker adds the
// policy.
type ListResult struct {
	Project   *Project
	Secrets   []SecretMeta
	Cooldowns []Cooldown
	// Unlinked is a synced project layer this repository could link.
	Unlinked *UnlinkedMatch
}

// Policy is the normative block of `list` (R-API-06).
type Policy struct {
	Can       []string   `json:"can"`
	Cannot    []string   `json:"cannot"`
	Layers    []string   `json:"layers"`
	Scopes    []string   `json:"scopes"`
	Cooldowns []Cooldown `json:"cooldowns"`
}

// UnlinkedMatch names a synced project layer this repository could link.
type UnlinkedMatch struct {
	Label string `json:"label"`
}

// ListResponse is the `list` success payload.
type ListResponse struct {
	OK            bool           `json:"ok"`
	Project       *Project       `json:"project"`
	Secrets       []SecretMeta   `json:"secrets"`
	UnlinkedMatch *UnlinkedMatch `json:"unlinked_match"`
	Policy        Policy         `json:"policy"`
}

// ExecResponse is the `exec` success payload.
type ExecResponse struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	Redactions int    `json:"redactions"`
	Truncated  bool   `json:"truncated"`
}

// GrantResponse is the `grant` success payload.
type GrantResponse struct {
	OK    bool      `json:"ok"`
	Grant GrantInfo `json:"grant"`
}

// RevokeResponse is the `revoke` success payload.
type RevokeResponse struct {
	OK      bool `json:"ok"`
	Revoked int  `json:"revoked"`
}

// Ref is one handle a `request` returns.
type Ref struct {
	Name  string `json:"name"`
	Ref   string `json:"ref"`
	Layer string `json:"layer"`
}

// RequestResponse is the `request` success payload.
type RequestResponse struct {
	OK    bool      `json:"ok"`
	Refs  []Ref     `json:"refs"`
	Ref   string    `json:"ref,omitempty"`
	Layer string    `json:"layer,omitempty"`
	Grant GrantInfo `json:"grant"`
}

// ManageResponse is the `manage` success payload.
type ManageResponse struct {
	OK      bool    `json:"ok"`
	Applied bool    `json:"applied"`
	Action  string  `json:"action"`
	Name    string  `json:"name"`
	Layer   *string `json:"layer"`
}

// Info is what a backend reports for `capabilities`.
type Info struct {
	Keychain       string
	PromptBackends []string
	Streaming      bool
}

// Backend implements the operations. Every method gets the validated
// envelope: its Cwd and Session, never the process ones, decide layers and
// grants. An error that is a refusal.Refusal is returned as is; any other
// error becomes `internal` with a fixed message.
type Backend interface {
	List(ctx context.Context, e Envelope) (ListResult, error)
	Exec(ctx context.Context, e Envelope, r ExecRequest) (ExecResponse, error)
	Grant(ctx context.Context, e Envelope, r GrantRequest) (GrantResponse, error)
	Revoke(ctx context.Context, e Envelope, r RevokeRequest) (RevokeResponse, error)
	Request(ctx context.Context, e Envelope, r RequestRequest) (RequestResponse, error)
	Manage(ctx context.Context, e Envelope, r ManageRequest) (ManageResponse, error)
	Info() Info
}

// Auditor is implemented by a Backend that keeps an audit log. Handle calls
// Refused for every refusal of a request whose envelope was valid (so the
// session is known), after the answer is decided and before it is returned.
// A request that fails the envelope check (contract, op, session, cwd) has no
// session to attribute and is not reported. The refusal carries a fixed
// message and at most a validated secret name; the implementation must record
// nothing else (no command, no reason, no field values). It is best effort:
// it cannot change the answer.
type Auditor interface {
	Refused(e Envelope, rf refusal.Refusal)
}
