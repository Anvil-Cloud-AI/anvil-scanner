// Package backup handles configuration snapshot and restore. It is
// the Go port of python/anvil_scanner/backup.py.
//
// Snapshots capture the current state of hardening-relevant files
// (sshd_config, pam.d/, firewall rules, selected launchd plists)
// before anvil-scanner makes any changes, so the user can roll back.
package backup
