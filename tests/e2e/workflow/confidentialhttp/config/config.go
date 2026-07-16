package config

// Config is the workflow configuration, passed at deploy time.
// The JSON field names match HTTPWorkflowConfig in
// system-tests/tests/test-helpers so that CompileAndDeployWorkflow
// can generate the config file automatically.
type Config struct {
	// AuthorizedKey is the public key (EVM address format, e.g. 0x...) used to sign HTTP trigger requests.
	AuthorizedKey string `json:"authorizedKey" yaml:"authorizedKey"`
	// URL is the recipient endpoint where the workflow POSTs confidential-http results.
	URL string `json:"url" yaml:"url"`
}
