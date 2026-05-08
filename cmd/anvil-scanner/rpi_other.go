//go:build darwin

package main

import "github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"

func runRPIChecks(_ *scan.CheckBuilder) (isRPi bool, rpiModel string) {
	return false, ""
}
