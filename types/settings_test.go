package types

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This is a wire format the untrusted host controls, so the migration plan asks
// for it to be pinned: a policy switch added for the migration must not slip in
// unnoticed. One did, briefly -- allowInsecureArtifactHttp -- and was removed
// again in favour of the pre-existing --allow-reconfig marker, which is measured
// into the PCR and so cannot be set by the host. The egress migration therefore
// leaves this surface exactly as origin/main shipped it, and the next addition
// takes a deliberate diff here.
func TestWorkflowSettingsJSONSurfaceUnchanged(t *testing.T) {
	want := []string{
		"storageKey",
		"storageServiceUrl",
		"storageServiceTls",
		"gatewayUrl",
		"maxBinarySize",
		"binaryFetchTimeout",
		"maxCacheBytes",
		"requestTimeout",
		"gatewayRequestTimeout",
		"executionTimeout",
		"workflowGracePeriod",
	}

	settings := reflect.TypeOf(WorkflowSettings{})
	got := make([]string, 0, settings.NumField())
	for i := range settings.NumField() {
		tag, _, _ := strings.Cut(settings.Field(i).Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		got = append(got, tag)
	}

	require.ElementsMatch(t, want, got,
		"the settings JSON surface changed; the untrusted host controls this, so add a field only deliberately")
}
