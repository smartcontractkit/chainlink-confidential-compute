package util

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const CapabilityDir = "integration_tests_temp"

func DeployCapability(t *testing.T, capabilityName string) (string, error) {
	projectPath := "../"
	outputBinary := CapabilityDir + "/" + capabilityName
	absoluteBinaryPath, err := filepath.Abs(outputBinary)
	require.NoError(t, err)

	cmd := exec.Command("go", "build", "-gcflags", "all=-N -l", "-o", absoluteBinaryPath)
	cmd.Dir = projectPath
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	return absoluteBinaryPath, nil
}

func CleanupCapabilityDir() {
	err := os.RemoveAll(CapabilityDir)
	if err != nil {
		log.Printf("Failed to remove directory: %v", err)
	}
}
