package environment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	crescriptenv "github.com/smartcontractkit/chainlink/core/scripts/cre/environment/environment"
	creenv "github.com/smartcontractkit/chainlink/system-tests/lib/cre/environment"

	envconfig "github.com/smartcontractkit/chainlink/system-tests/lib/cre/environment/config"
	libformat "github.com/smartcontractkit/chainlink/system-tests/lib/format"
)

func initRoot() {
	rootPath, rootPathErr := os.Getwd()
	if rootPathErr != nil {
		fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", rootPathErr)
		os.Exit(1)
	}
	binDir := filepath.Join(rootPath, "bin")
	if _, err := os.Stat(binDir); os.IsNotExist(err) {
		if err := os.Mkdir(binDir, 0o755); err != nil {
			panic(fmt.Errorf("failed to create bin directory: %w", err))
		}
	}
}

func preConfigure(ctx context.Context, relativePathToRepoRoot string) (*envconfig.Config, error) {
	// Clean up any existing state files before starting. Order matters: prior
	// subtests may have left state/local_cre.toml describing a different
	// topology (e.g. the engine subtest's relay DON), and RunSetup will
	// otherwise read+merge that stale state into the new env. Purge the
	// state dir BEFORE RunSetup, not after.
	_ = StopCreEnvironment(relativePathToRepoRoot)

	err := framework.RemoveTestContainers()
	if err != nil {
		return nil, errors.Wrap(err, "failed to remove test containers")
	}
	defer func() {
		crescriptenv.StartCmdRecoverHandlerFunc(nil, nil, true, cleanupWait)
	}()

	if cleanUpErr := envconfig.RemoveAllEnvironmentStateDir(relativePathToRepoRoot); cleanUpErr != nil {
		return nil, errors.Wrap(cleanUpErr, "failed to clean up environment state files")
	}

	// Recover the user-supplied CTF_CONFIGS and re-prepend our default. A
	// previous call here may have composed "<default>,<user>", so strip
	// that prefix (idempotent). If a subtest overrode CTF_CONFIGS via
	// t.Setenv since the last call, the override is honored.
	userConfigs := strings.TrimPrefix(os.Getenv("CTF_CONFIGS"), defaultCapabilitiesConfigFile+",")
	ctfConfigs := defaultCapabilitiesConfigFile
	if userConfigs != "" {
		ctfConfigs = defaultCapabilitiesConfigFile + "," + userConfigs
	}
	if err := os.Setenv("CTF_CONFIGS", ctfConfigs); err != nil {
		return nil, fmt.Errorf("failed to set CTF_CONFIGS environment variable: %w", err)
	}

	setupErr := crescriptenv.RunSetup(ctx, crescriptenv.SetupConfig{ConfigPath: crescriptenv.DefaultSetupConfigPath}, true, false, false, relativePathToRepoRoot)
	if setupErr != nil {
		return nil, errors.Wrap(setupErr, "failed to run setup")
	}

	crescriptenv.PrintCRELogo()

	if pkErr := creenv.SetDefaultPrivateKeyIfEmpty(blockchain.DefaultAnvilPrivateKey); pkErr != nil {
		return nil, errors.Wrap(pkErr, "failed to set default private key")
	}

	// set TESTCONTAINERS_RYUK_DISABLED to true to disable Ryuk, so that Ryuk doesn't destroy the containers, when the command ends
	setErr := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	if setErr != nil {
		return nil, fmt.Errorf("failed to set TESTCONTAINERS_RYUK_DISABLED environment variable: %w", setErr)
	}

	in := &envconfig.Config{}
	if err := in.Load(os.Getenv("CTF_CONFIGS")); err != nil {
		return nil, errors.Wrap(err, "failed to load environment configuration")
	}

	return in, nil
}

func saveOutput(in *envconfig.Config, output *creenv.SetupOutput, relativePathToRepoRoot string) error {
	fmt.Print(libformat.PurpleText("\nEnvironment setup completed successfully\n\n"))
	fmt.Print("To terminate execute:`go run . env stop`\n\n")

	addresses, aErr := output.CreEnvironment.CldfEnvironment.DataStore.Addresses().Fetch()
	if aErr != nil {
		return errors.Wrap(aErr, "failed to fetch addresses from datastore")
	}

	if err := in.SetAddresses(addresses); err != nil {
		return errors.Wrap(err, "failed to set addresses on config")
	}

	storeErr := in.Store(envconfig.MustLocalCREStateFileAbsPath(relativePathToRepoRoot))
	if storeErr != nil {
		return errors.Wrap(storeErr, "failed to store local CRE state")
	}

	return nil
}
