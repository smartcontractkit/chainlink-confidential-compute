package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	log.Default().Println("Starting enclave ticker with chrony PTP time synchronization...")

	time.Sleep(time.Second * 2)

	clockSource := getClockSource()
	availableSources := getAvailableClockSources()
	log.Default().Printf("Current clock source: %s", clockSource)
	log.Default().Printf("Available clock sources: %s", availableSources)
	if clockSource != "kvm-clock" {
		panic("Clock source is not kvm-clock")
	}

	chronyStatus := getChronyStatus()
	log.Default().Printf("Chrony tracking status: \n%s", chronyStatus)

	for i := 0; i < 1000; i++ {
		now := time.Now()
		chronySources := getChronySources()

		log.Default().Printf("Time: %d (formatted: %s)", now.Unix(), now.Format(time.RFC3339))
		log.Default().Printf("Chrony sources: \n%s", chronySources)

		if strings.Contains(chronySources, "* PHC") {
			log.Default().Printf("PTP time synchronization is active")
		}

		if i%5 == 0 {
			log.Default().Printf("Chrony tracking update: \n%s", getChronyStatus())
		}

		time.Sleep(time.Second * 5)
	}
}

func getClockSource() string {
	data, err := os.ReadFile("/sys/devices/system/clocksource/clocksource0/current_clocksource")
	if err != nil {
		return fmt.Sprintf("error reading clock source: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func getAvailableClockSources() string {
	data, err := os.ReadFile("/sys/devices/system/clocksource/clocksource0/available_clocksource")
	if err != nil {
		return fmt.Sprintf("error reading available clock sources: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func getChronyStatus() string {
	cmd := exec.Command("chronyc", "tracking")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error getting chrony status: %v", err)
	}
	return string(output)
}

func getChronySources() string {
	cmd := exec.Command("chronyc", "sources")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error getting chrony sources: %v", err)
	}
	return string(output)
}
