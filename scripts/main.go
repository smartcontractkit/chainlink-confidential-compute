package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

type PCRSet struct {
	PCR0 string
	PCR1 string
	PCR2 string
}

var validMeasurements = []PCRSet{
	{
		PCR0: "b43fb0337b472576b44bc5de4c460d4cf3124bbe16490663070dbf3c6327711fb1fd708ee20cf5585918d73a74aa16c1",
		PCR1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
		PCR2: "b38ecfc45793150d44918886b209af062cc16f3538664fb5a7ebe2bd65100f26bda799c089dae4f485926859832981af",
	},
	{
		PCR0: "58086c660d61bef55a5bfa85b2ff1f3f8fd209078dd6dee93d14ed126d5b353065a095739bfb3a06cdef6904fc2b2f83",
		PCR1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
		PCR2: "76593fabe8c6253eacb79ae788733fa030de052a5dd059d6770e637de6993ae117951c28932c16668196e64347433b7e",
	},
}

// Update this with your desired on-chain config.
var config = types.EnclavesList{
	Enclaves: []types.Enclave{{
		EnclaveID:        sha256.Sum256([]byte("enclave-1")),
		EnclaveURL:       "https://confidential-http.enclaves.chain.link",
		EnclaveType:      types.EnclaveTypeNitro,
		EnclaveExtraData: []byte(""),
		Region:           "us-west-2",
	}, {
		EnclaveID:        sha256.Sum256([]byte("enclave-2")),
		EnclaveURL:       "https://confidential-http-2.enclaves.chain.link",
		EnclaveType:      types.EnclaveTypeNitro,
		EnclaveExtraData: []byte(""),
		Region:           "us-west-2",
	}},
}

type EncodedConfig struct {
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "gen-config-yaml":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: gen-config-yaml requires an output YAML file path\n")
			printUsage()
			os.Exit(1)
		}
		outputFile := os.Args[2]

		for i := range config.Enclaves {
			var trustedValues [][]byte
			for _, measurement := range validMeasurements {
				// Decode PCR0
				pcr0, err := hex.DecodeString(measurement.PCR0)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error decoding PCR0 hex: %v\n", err)
					os.Exit(1)
				}
				// Decode PCR1
				pcr1, err := hex.DecodeString(measurement.PCR1)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error decoding PCR1 hex: %v\n", err)
					os.Exit(1)
				}
				// Decode PCR2
				pcr2, err := hex.DecodeString(measurement.PCR2)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error decoding PCR2 hex: %v\n", err)
					os.Exit(1)
				}
				pcrs := nitro.PCRs{
					PCR0: pcr0,
					PCR1: pcr1,
					PCR2: pcr2,
				}
				mbytes, err := json.Marshal(pcrs)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error marshaling PCRs to JSON: %v\n", err)
					os.Exit(1)
				}
				trustedValues = append(trustedValues, mbytes)
			}
			config.Enclaves[i].TrustedValues = trustedValues
		}

		wrappedConfig, err := values.WrapMap(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error wrapping config: %v\n", err)
			os.Exit(1)
		}
		protoMap := values.Proto(wrappedConfig).GetMapValue()
		if protoMap == nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get map value from wrapped config\n")
			os.Exit(1)
		}

		// Convert proto to JSON using protojson
		marshaler := protojson.MarshalOptions{
			Multiline:       true,
			EmitUnpopulated: false,
		}
		jsonBytes, err := marshaler.Marshal(protoMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling proto to JSON: %v\n", err)
			os.Exit(1)
		}

		// Convert JSON to a Go map
		var jsonMap map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling JSON: %v\n", err)
			os.Exit(1)
		}

		// Convert map to YAML with 2-space indentation
		var buf bytes.Buffer
		encoder := yaml.NewEncoder(&buf)
		encoder.SetIndent(2)

		if err := encoder.Encode(jsonMap); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding to YAML: %v\n", err)
			os.Exit(1)
		}

		if err := encoder.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing YAML encoder: %v\n", err)
			os.Exit(1)
		}

		yamlBytes := buf.Bytes()

		// Write to file
		if err := os.WriteFile(outputFile, yamlBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing YAML file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully wrote YAML config to: %s\n", outputFile)

	case "encrypt-apikey":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Error: encrypt-apikey requires <api-key> <public-key>\n")
			printUsage()
			os.Exit(1)
		}
		apiKey := os.Args[2]
		publicKeyStr := os.Args[3]

		// Parse the public key (try hex first, then base64)
		var publicKey [32]byte
		decoded, err := hex.DecodeString(publicKeyStr)
		if err != nil || len(decoded) != 32 {
			// Try base64
			decoded, err = base64.StdEncoding.DecodeString(publicKeyStr)
			if err != nil || len(decoded) != 32 {
				fmt.Fprintf(os.Stderr, "Error: public key must be 32 bytes in hex or base64 format\n")
				os.Exit(1)
			}
		}
		copy(publicKey[:], decoded)

		// Encrypt the API key using box.SealAnonymous
		apiKeyBytes := []byte(apiKey)
		encrypted, err := box.SealAnonymous(nil, apiKeyBytes, &publicKey, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting API key: %v\n", err)
			os.Exit(1)
		}

		// Output both hex and base64 encoded versions
		fmt.Printf("Encrypted API Key:\n")
		fmt.Printf("Hex:    %s\n", hex.EncodeToString(encrypted))
		fmt.Printf("Base64: %s\n", base64.StdEncoding.EncodeToString(encrypted))

	case "encrypt-env":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: encrypt-env requires <public-key> [env-file]\n")
			printUsage()
			os.Exit(1)
		}
		publicKeyStr := os.Args[2]
		envFile := ".env"
		if len(os.Args) >= 4 {
			envFile = os.Args[3]
		}

		// Parse the public key
		var publicKey [32]byte
		decoded, err := hex.DecodeString(publicKeyStr)
		if err != nil || len(decoded) != 32 {
			decoded, err = base64.StdEncoding.DecodeString(publicKeyStr)
			if err != nil || len(decoded) != 32 {
				fmt.Fprintf(os.Stderr, "Error: public key must be 32 bytes in hex or base64 format\n")
				os.Exit(1)
			}
		}
		copy(publicKey[:], decoded)

		// Read the .env file
		file, err := os.Open(envFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", envFile, err)
			os.Exit(1)
		}
		defer func() {
			if err := file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
			}
		}()

		fmt.Printf("Encrypting secrets from %s:\n\n", envFile)
		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())

			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Parse KEY=VALUE format
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Warning: Skipping invalid line %d: %s\n", lineNum, line)
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Remove quotes if present
			value = strings.Trim(value, "\"'")

			// Encrypt the value
			encrypted, err := box.SealAnonymous(nil, []byte(value), &publicKey, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting %s: %v\n", key, err)
				continue
			}

			fmt.Printf("%s:\n", key)
			fmt.Printf("  Hex:    %s\n", hex.EncodeToString(encrypted))
			fmt.Printf("  Base64: %s\n\n", base64.StdEncoding.EncodeToString(encrypted))
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", envFile, err)
			os.Exit(1)
		}

	case "encrypt-batch":
		pubkeysFile := "pubkeys.txt"
		secretsFile := "secrets.txt"
		outputFile := "encrypted_output.txt"

		if len(os.Args) >= 3 {
			pubkeysFile = os.Args[2]
		}
		if len(os.Args) >= 4 {
			secretsFile = os.Args[3]
		}
		if len(os.Args) >= 5 {
			outputFile = os.Args[4]
		}

		// Read public keys
		pubkeysData, err := os.ReadFile(pubkeysFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", pubkeysFile, err)
			os.Exit(1)
		}
		pubkeyLines := strings.Split(strings.TrimSpace(string(pubkeysData)), "\n")

		// Read secrets
		secretsData, err := os.ReadFile(secretsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", secretsFile, err)
			os.Exit(1)
		}
		secretLines := strings.Split(strings.TrimSpace(string(secretsData)), "\n")

		if len(pubkeyLines) != len(secretLines) {
			fmt.Fprintf(os.Stderr, "Error: Number of public keys (%d) doesn't match number of secrets (%d)\n", len(pubkeyLines), len(secretLines))
			os.Exit(1)
		}

		var encryptedLines []string

		fmt.Printf("Encrypting %d secrets...\n", len(secretLines))
		for i := range pubkeyLines {
			pubkeyStr := strings.TrimSpace(pubkeyLines[i])
			secret := strings.TrimSpace(secretLines[i])

			// Skip empty lines
			if pubkeyStr == "" || secret == "" {
				continue
			}

			// Parse the public key
			var publicKey [32]byte
			decoded, err := hex.DecodeString(pubkeyStr)
			if err != nil || len(decoded) != 32 {
				decoded, err = base64.StdEncoding.DecodeString(pubkeyStr)
				if err != nil || len(decoded) != 32 {
					fmt.Fprintf(os.Stderr, "Error: public key at line %d must be 32 bytes in hex or base64 format\n", i+1)
					os.Exit(1)
				}
			}
			copy(publicKey[:], decoded)

			// Encrypt the secret
			encrypted, err := box.SealAnonymous(nil, []byte(secret), &publicKey, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting secret at line %d: %v\n", i+1, err)
				os.Exit(1)
			}

			encryptedHex := hex.EncodeToString(encrypted)
			encryptedLines = append(encryptedLines, encryptedHex)
			fmt.Printf("  [%d/%d] Encrypted\n", i+1, len(secretLines))
		}

		// Write to output file
		outputData := strings.Join(encryptedLines, "\n") + "\n"
		if err := os.WriteFile(outputFile, []byte(outputData), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", outputFile, err)
			os.Exit(1)
		}

		fmt.Printf("\nSuccessfully encrypted %d secrets to %s\n", len(encryptedLines), outputFile)

	case "decode-config-yaml":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: decode-config-yaml requires <config-yaml-file>\n")
			printUsage()
			os.Exit(1)
		}
		configFile := os.Args[2]

		// Read the config YAML file
		yamlData, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}

		// Parse YAML
		var configData map[string]interface{}
		if err := yaml.Unmarshal(yamlData, &configData); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
			os.Exit(1)
		}

		// Navigate to the enclaves configuration
		fields, ok := configData["fields"].(map[string]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: 'fields' not found or invalid format\n")
			os.Exit(1)
		}

		enclavesField, ok := fields["Enclaves"].(map[string]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: 'Enclaves' field not found\n")
			os.Exit(1)
		}

		listValue, ok := enclavesField["listValue"].(map[string]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: 'listValue' not found in Enclaves\n")
			os.Exit(1)
		}

		enclaveFields, ok := listValue["fields"].([]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: 'fields' not found in listValue\n")
			os.Exit(1)
		}

		fmt.Printf("Decoded %d enclave(s) from %s:\n\n", len(enclaveFields), configFile)

		// Collect unique PCR sets
		pcrSets := make(map[string]nitro.PCRs)

		for i, enclaveEntry := range enclaveFields {
			enclaveMap, ok := enclaveEntry.(map[string]interface{})
			if !ok {
				continue
			}

			mapValue, ok := enclaveMap["mapValue"].(map[string]interface{})
			if !ok {
				continue
			}

			enclaveFieldsMap, ok := mapValue["fields"].(map[string]interface{})
			if !ok {
				continue
			}

			fmt.Printf("Enclave #%d:\n", i+1)
			fmt.Println("====================")

			// Extract EnclaveURL
			if urlField, ok := enclaveFieldsMap["EnclaveURL"].(map[string]interface{}); ok {
				if url, ok := urlField["stringValue"].(string); ok {
					fmt.Printf("  URL: %s\n", url)
				}
			}

			// Extract EnclaveType
			if typeField, ok := enclaveFieldsMap["EnclaveType"].(map[string]interface{}); ok {
				if enclaveType, ok := typeField["stringValue"].(string); ok {
					fmt.Printf("  Type: %s\n", enclaveType)
				}
			}

			// Extract EnclaveID
			if idField, ok := enclaveFieldsMap["EnclaveID"].(map[string]interface{}); ok {
				if idBase64, ok := idField["bytesValue"].(string); ok {
					idBytes, err := base64.StdEncoding.DecodeString(idBase64)
					if err == nil {
						fmt.Printf("  ID (Base64): %s\n", idBase64)
						fmt.Printf("  ID (Hex): %s\n", hex.EncodeToString(idBytes))
					}
				}
			}

			// Extract and decode TrustedValues (PCRs)
			if trustedField, ok := enclaveFieldsMap["TrustedValues"].(map[string]interface{}); ok {
				if trustedListValue, ok := trustedField["listValue"].(map[string]interface{}); ok {
					if trustedFields, ok := trustedListValue["fields"].([]interface{}); ok {
						fmt.Printf("  Trusted Values (PCRs):\n")
						for j, trustedEntry := range trustedFields {
							trustedEntryMap, ok := trustedEntry.(map[string]interface{})
							if !ok {
								continue
							}
							trustedBase64, ok := trustedEntryMap["bytesValue"].(string)
							if !ok {
								continue
							}
							trustedBytes, err := base64.StdEncoding.DecodeString(trustedBase64)
							if err != nil {
								fmt.Printf("    [%d] Error decoding base64: %v\n", j+1, err)
								continue
							}
							var pcrs nitro.PCRs
							if err := json.Unmarshal(trustedBytes, &pcrs); err != nil {
								fmt.Printf("    [%d] Error parsing JSON: %v\n", j+1, err)
								fmt.Printf("    [%d] Raw: %s\n", j+1, string(trustedBytes))
								continue
							}
							pcr0Hex := hex.EncodeToString(pcrs.PCR0)
							pcr1Hex := hex.EncodeToString(pcrs.PCR1)
							pcr2Hex := hex.EncodeToString(pcrs.PCR2)
							fmt.Printf("    [%d] PCR0: %s\n", j+1, pcr0Hex)
							fmt.Printf("    [%d] PCR1: %s\n", j+1, pcr1Hex)
							fmt.Printf("    [%d] PCR2: %s\n", j+1, pcr2Hex)

							// Store unique PCR sets
							key := pcr0Hex + pcr1Hex + pcr2Hex
							pcrSets[key] = pcrs
						}
					}
				}
			}

			fmt.Println()
		}

		// Print unique PCR sets in Go code format
		fmt.Println("======================================")
		fmt.Println("Unique PCR Measurements (Go format):")
		fmt.Println("======================================")
		fmt.Println("var validMeasurements = []PCRSet{")
		for _, pcrs := range pcrSets {
			fmt.Println("\t{")
			fmt.Printf("\t\tPCR0: \"%s\",\n", hex.EncodeToString(pcrs.PCR0))
			fmt.Printf("\t\tPCR1: \"%s\",\n", hex.EncodeToString(pcrs.PCR1))
			fmt.Printf("\t\tPCR2: \"%s\",\n", hex.EncodeToString(pcrs.PCR2))
			fmt.Println("\t},")
		}
		fmt.Println("}")

	case "decode-pipeline-enclaves":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: decode-pipeline-enclaves requires <pipeline-yaml-file>\n")
			printUsage()
			os.Exit(1)
		}
		pipelineFile := os.Args[2]

		// Read the pipeline YAML file
		yamlData, err := os.ReadFile(pipelineFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", pipelineFile, err)
			os.Exit(1)
		}

		// Parse YAML
		var pipelineData map[string]interface{}
		if err := yaml.Unmarshal(yamlData, &pipelineData); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
			os.Exit(1)
		}

		// Navigate to the enclaves configuration
		changesets, ok := pipelineData["changesets"].([]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: 'changesets' not found or invalid format\n")
			os.Exit(1)
		}

		type DecodedEnclave struct {
			URL        string            `json:"url"`
			Type       string            `json:"type"`
			IDBase64   string            `json:"id_base64"`
			IDHex      string            `json:"id_hex"`
			PCRs       map[string]string `json:"pcrs,omitempty"`
			AuthHeader string            `json:"auth_header,omitempty"`
			ExtraData  string            `json:"extra_data,omitempty"`
		}

		type OnChainEnclaveConfig struct {
			SourceFile string           `json:"source_file"`
			Enclaves   []DecodedEnclave `json:"enclaves"`
		}

		var enclavesFound bool
		var decodedEnclaves []DecodedEnclave

		for _, changeset := range changesets {
			changesetMap, ok := changeset.(map[string]interface{})
			if !ok {
				continue
			}

			capabilityRegistry, ok := changesetMap["capability_registry_add_capability"].(map[string]interface{})
			if !ok {
				continue
			}

			payload, ok := capabilityRegistry["payload"].(map[string]interface{})
			if !ok {
				continue
			}

			capabilityConfigs, ok := payload["capabilityConfigs"].([]interface{})
			if !ok || len(capabilityConfigs) == 0 {
				continue
			}

			firstConfig, ok := capabilityConfigs[0].(map[string]interface{})
			if !ok {
				continue
			}

			configSection, ok := firstConfig["config"].(map[string]interface{})
			if !ok {
				continue
			}

			defaultConfig, ok := configSection["defaultConfig"].(map[string]interface{})
			if !ok {
				continue
			}

			fields, ok := defaultConfig["fields"].(map[string]interface{})
			if !ok {
				continue
			}

			enclavesField, ok := fields["Enclaves"].(map[string]interface{})
			if !ok {
				continue
			}

			listValue, ok := enclavesField["listValue"].(map[string]interface{})
			if !ok {
				continue
			}

			enclaveFields, ok := listValue["fields"].([]interface{})
			if !ok {
				continue
			}

			enclavesFound = true
			fmt.Printf("Found %d enclave(s) in %s:\n\n", len(enclaveFields), pipelineFile)

			for i, enclaveEntry := range enclaveFields {
				enclaveMap, ok := enclaveEntry.(map[string]interface{})
				if !ok {
					continue
				}

				mapValue, ok := enclaveMap["mapValue"].(map[string]interface{})
				if !ok {
					continue
				}

				enclaveFields, ok := mapValue["fields"].(map[string]interface{})
				if !ok {
					continue
				}

				decoded := DecodedEnclave{}

				fmt.Printf("Enclave #%d:\n", i+1)
				fmt.Println("====================")

				// Extract EnclaveURL
				if urlField, ok := enclaveFields["EnclaveURL"].(map[string]interface{}); ok {
					if url, ok := urlField["stringValue"].(string); ok {
						decoded.URL = url
						fmt.Printf("  URL: %s\n", url)
					}
				}

				// Extract EnclaveType
				if typeField, ok := enclaveFields["EnclaveType"].(map[string]interface{}); ok {
					if enclaveType, ok := typeField["stringValue"].(string); ok {
						decoded.Type = enclaveType
						fmt.Printf("  Type: %s\n", enclaveType)
					}
				}

				// Extract EnclaveID
				if idField, ok := enclaveFields["EnclaveID"].(map[string]interface{}); ok {
					if idBase64, ok := idField["bytesValue"].(string); ok {
						idBytes, err := base64.StdEncoding.DecodeString(idBase64)
						if err == nil {
							decoded.IDBase64 = idBase64
							decoded.IDHex = hex.EncodeToString(idBytes)
							fmt.Printf("  ID (Base64): %s\n", idBase64)
							fmt.Printf("  ID (Hex): %s\n", hex.EncodeToString(idBytes))
						}
					}
				}

				// Extract and decode TrustedValues (PCRs)
				if trustedField, ok := enclaveFields["TrustedValues"].(map[string]interface{}); ok {
					if trustedBase64, ok := trustedField["bytesValue"].(string); ok {
						trustedBytes, err := base64.StdEncoding.DecodeString(trustedBase64)
						if err == nil {
							var pcrs nitro.PCRs
							if err := json.Unmarshal(trustedBytes, &pcrs); err == nil {
								decoded.PCRs = map[string]string{
									"pcr0": hex.EncodeToString(pcrs.PCR0),
									"pcr1": hex.EncodeToString(pcrs.PCR1),
									"pcr2": hex.EncodeToString(pcrs.PCR2),
								}
								fmt.Printf("  Trusted Values (PCRs):\n")
								fmt.Printf("    PCR0: %s\n", hex.EncodeToString(pcrs.PCR0))
								fmt.Printf("    PCR1: %s\n", hex.EncodeToString(pcrs.PCR1))
								fmt.Printf("    PCR2: %s\n", hex.EncodeToString(pcrs.PCR2))
							} else {
								fmt.Printf("  Trusted Values (Raw Base64): %s\n", trustedBase64)
							}
						}
					}
				}

				// Extract EnclaveAuthHeader
				if authField, ok := enclaveFields["EnclaveAuthHeader"].(map[string]interface{}); ok {
					if auth, ok := authField["stringValue"].(string); ok && auth != "" {
						decoded.AuthHeader = auth
						fmt.Printf("  Auth Header: %s\n", auth)
					}
				}

				// Extract EnclaveExtraData
				if extraField, ok := enclaveFields["EnclaveExtraData"].(map[string]interface{}); ok {
					if extraBase64, ok := extraField["bytesValue"].(string); ok && extraBase64 != "" {
						extraBytes, err := base64.StdEncoding.DecodeString(extraBase64)
						if err == nil && len(extraBytes) > 0 {
							decoded.ExtraData = string(extraBytes)
							fmt.Printf("  Extra Data: %s\n", string(extraBytes))
						}
					}
				}

				decodedEnclaves = append(decodedEnclaves, decoded)
				fmt.Println()
			}
		}

		if !enclavesFound {
			fmt.Fprintf(os.Stderr, "Error: No enclaves configuration found in pipeline file\n")
			os.Exit(1)
		}

		// Write to JSON file
		outputConfig := OnChainEnclaveConfig{
			SourceFile: pipelineFile,
			Enclaves:   decodedEnclaves,
		}

		jsonBytes, err := json.MarshalIndent(outputConfig, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}

		outputFile := "current_on_chain_enclave_configs.json"
		if err := os.WriteFile(outputFile, jsonBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully wrote decoded enclaves to: %s\n", outputFile)

	case "validate-cld-pr":
		runValidateCLDPR(os.Args[2:])

	case "check-prod":
		runCheckProd(os.Args[2:])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: scripts <command> [args]")
	fmt.Println("\nAvailable commands:")
	fmt.Println("  gen-config-yaml <output.yaml>          Generate YAML config from hardcoded config")
	fmt.Println("                                          If output file not specified, writes to stdout")
	fmt.Println("  decode-config-yaml <config.yaml>       Decode a generated config YAML to show measurements")
	fmt.Println("                                          Reverses gen-config-yaml output to show PCR values")
	fmt.Println("  encrypt-apikey <api-key> <public-key>  Encrypt an API key using NaCl box.SealAnonymous")
	fmt.Println("                                          public-key can be hex or base64 encoded (32 bytes)")
	fmt.Println("  encrypt-env <public-key> [env-file]    Encrypt all secrets from a .env file (default: .env)")
	fmt.Println("                                          Reads KEY=VALUE pairs and encrypts each value")
	fmt.Println("  encrypt-batch [pubkeys] [secrets] [output]")
	fmt.Println("                                          Batch encrypt secrets with matching public keys")
	fmt.Println("                                          Defaults: pubkeys.txt, secrets.txt, encrypted_output.txt")
	fmt.Println("                                          Each line in pubkeys.txt matches a line in secrets.txt")
	fmt.Println("  decode-pipeline-enclaves <pipeline.yaml>")
	fmt.Println("                                          Decode and display enclaves from a pipeline YAML file")
	fmt.Println("                                          Extracts enclaves from capability_registry_add_capability")
	fmt.Println("  validate-cld-pr <pr-url-or-number> [--repo <owner/repo>] [--api-key <key>]")
	fmt.Println("                                          Fetch enclave measurements from a chainlink-deployments PR")
	fmt.Println("                                          and validate them against the live attested /publicKeys")
	fmt.Println("                                          response from each enclave. Defaults: repo")
	fmt.Println("                                          smartcontractkit/chainlink-deployments, api-key from")
	fmt.Println("                                          ENCLAVE_API_KEY env var")
	fmt.Println("  check-prod [api-key]                   Fetch the live attested /publicKeys response from each")
	fmt.Println("                                          production enclave and report which known measurement")
	fmt.Println("                                          validates it. api-key from ENCLAVE_API_KEY env var or arg")
}
