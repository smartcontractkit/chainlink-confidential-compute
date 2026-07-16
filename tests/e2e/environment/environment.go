// The environment package provides functions that initialize a local CRE environment.
// environment.go contains the core logic to start and stop a CRE environment.
// lib.go contains helper functions for working with the CRE environment.
// vendor.go contains functions directly vendored from Chainlink core.
package environment

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"time"

	"github.com/pkg/errors"

	envconfig "github.com/smartcontractkit/chainlink/system-tests/lib/cre/environment/config"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/features/sets"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/flags"

	crescriptenv "github.com/smartcontractkit/chainlink/core/scripts/cre/environment/environment"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre"
	gateway "github.com/smartcontractkit/chainlink/system-tests/lib/cre/don/gateway"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	defaultCapabilitiesConfigFile = "configs/capability_defaults.toml"
	cleanupWait                   = time.Second * 15
)

// StartCreEnvironment sets up and starts a local CRE environment.
// afterSetup runs after plugin binaries are built (via loopinstall) but before
// containers are created. Use it to overwrite loopinstall binaries with locally
// built versions when testing local changes to a capability.
func StartCreEnvironment(ctx context.Context, relativePathToRepoRoot string, extraCapabilities []cre.InstallableCapability, afterSetup func() error, extraAllowedPorts []int, extraFeatures ...cre.Feature) error {
	initRoot()

	in, err := preConfigure(ctx, relativePathToRepoRoot)
	if err != nil {
		return err
	}

	if afterSetup != nil {
		if err := afterSetup(); err != nil {
			return errors.Wrap(err, "afterSetup callback failed")
		}
	}

	// Add extra capability flags to the workflow DON's capabilities list.
	// The TOML config defines the DON's base capabilities, but extra capabilities
	// (e.g. confidential-http, confidential-workflows) are registered dynamically.
	// Without this, job specs won't be delivered and on-chain registration is skipped,
	// because both check don.HasFlag(name) which reads from NodeSet.Capabilities.
	for _, c := range extraCapabilities {
		flag := c.Flag()
		for i, ns := range in.NodeSets {
			if slices.Contains(ns.DONTypes, "workflow") && !slices.Contains(ns.Capabilities, flag) {
				in.NodeSets[i].Capabilities = append(in.NodeSets[i].Capabilities, flag)
			}
		}
	}

	// confidential-workflows is declared on the workflow DON in workflow-don.toml
	// but chainlink-lib's built-in capabilityFlagsProvider doesn't know it yet.
	// Register it here so Config.Validate accepts the DON's declared capabilities
	// regardless of which test (HTTP or engine) triggered this path.
	extraFlags := []string{cre.DONTimeCapability, string(cre.ConfidentialRelayCapability), "confidential-workflows"}
	for _, c := range extraCapabilities {
		extraFlags = append(extraFlags, c.Flag())
	}
	for _, f := range extraFeatures {
		extraFlags = append(extraFlags, string(f.Flag()))
	}
	envDependencies := cre.NewEnvironmentDependencies(
		flags.NewExtensibleCapabilityFlagsProvider(extraFlags),
		cre.NewContractVersionsProvider(envconfig.DefaultContractSet()),
	)

	if err := in.Validate(envDependencies); err != nil {
		return errors.Wrap(err, "failed to validate test configuration")
	}

	capabilities := sets.New()
	for _, f := range extraFeatures {
		capabilities.Add(f)
	}

	allowedPorts := append([]int{}, in.Fake.Port, in.FakeHTTP.Port)
	allowedPorts = append(allowedPorts, extraAllowedPorts...)
	gatewayWhitelistConfig := gateway.WhitelistConfig{
		ExtraAllowedPorts:   allowedPorts,
		ExtraAllowedIPsCIDR: []string{"0.0.0.0/0"},
	}
	output, startErr := crescriptenv.StartCLIEnvironment(
		ctx,
		relativePathToRepoRoot,
		in,
		extraCapabilities,
		capabilities,
		nil,
		envDependencies,
		gatewayWhitelistConfig,
	)
	if startErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", startErr)
		fmt.Fprintf(os.Stderr, "Stack trace: %s\n", string(debug.Stack()))

		stopErr := StopCreEnvironment(relativePathToRepoRoot)
		if stopErr != nil {
			return errors.Wrap(stopErr, "failed to stop environment after startup error. ")
		}

		return errors.Wrap(startErr, "failed to start environment")
	}

	err = saveOutput(in, output, relativePathToRepoRoot)
	if err != nil {
		return errors.Wrap(err, "failed to save environment output")
	}

	return nil
}

func StopCreEnvironment(relativePathToRepoRoot string) error {
	removeErr := framework.RemoveTestContainers()
	if removeErr != nil {
		return errors.Wrap(removeErr, "failed to remove environment containers. Please remove them manually")
	}

	creStateFile := envconfig.MustLocalCREStateFileAbsPath(relativePathToRepoRoot)
	cErr := os.Remove(creStateFile)
	if cErr != nil {
		framework.L.Warn().Msgf("failed to remove local CRE state file: %s", cErr)
	} else {
		framework.L.Info().Msgf("removed local CRE state file: %s", creStateFile)
	}

	fmt.Println("Environment stopped successfully")
	return nil
}
