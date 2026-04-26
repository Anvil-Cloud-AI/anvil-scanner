//go:build linux

package main

import (
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

func runRPIChecks(b *scan.CheckBuilder) (isRPi bool, rpiModel string) {
	info := scan.DetectRPI()
	scan.RunRPIChecks(b, info)
	return info.IsPi, info.Model
}
