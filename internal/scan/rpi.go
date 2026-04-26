//go:build linux

package scan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// RPIInfo holds hardware/OS capabilities detected at startup on
// Raspberry Pi. Zero value is the non-Pi default (all booleans false).
// Probe it once via DetectRPI() and pass the result down to RunRPIChecks.
type RPIInfo struct {
	IsPi         bool
	Model        string
	HasGPIO      bool
	HasCamera    bool
	HasBluetooth bool
}

// DetectRPI probes the running system to determine whether it is a
// Raspberry Pi. On non-Linux builds this returns a zero RPIInfo (IsPi=false).
// The probe is cheap — it reads /proc/device-tree/model and /proc/cpuinfo,
// neither of which require elevated privileges.
func DetectRPI() RPIInfo {
	info := RPIInfo{}

	// Primary probe: device-tree model string
	if b, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		model := strings.TrimRight(string(b), "\x00")
		if strings.Contains(strings.ToLower(model), "raspberry pi") {
			info.IsPi = true
			info.Model = strings.TrimSpace(model)
		}
	}

	// Fallback: /proc/cpuinfo Hardware or Model line
	if !info.IsPi {
		if f, err := os.Open("/proc/cpuinfo"); err == nil {
			defer f.Close()
			s := bufio.NewScanner(f)
			for s.Scan() {
				line := s.Text()
				if strings.HasPrefix(line, "Hardware") && strings.Contains(line, "BCM") {
					info.IsPi = true
					info.Model = "Raspberry Pi (BCM SoC detected)"
					break
				}
				if strings.HasPrefix(line, "Model") && strings.Contains(line, "Raspberry Pi") {
					info.IsPi = true
					if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
						info.Model = strings.TrimSpace(parts[1])
					}
					break
				}
			}
		}
	}

	if !info.IsPi {
		return info
	}

	// Capability detection
	_, gpioSys := os.Stat("/sys/class/gpio")
	_, gpiochip := os.Stat("/dev/gpiochip0")
	info.HasGPIO = gpioSys == nil || gpiochip == nil

	_, camErr := os.Stat("/dev/video0")
	info.HasCamera = camErr == nil

	if btDir, err := os.Open("/sys/class/bluetooth"); err == nil {
		defer btDir.Close()
		entries, _ := btDir.Readdir(1)
		info.HasBluetooth = len(entries) > 0
	}

	return info
}

// RunRPIChecks executes RPI-001 through RPI-012. It is a no-op unless
// info.IsPi is true — callers on non-Pi Linux or macOS can call it
// unconditionally.
func RunRPIChecks(b *CheckBuilder, info RPIInfo) {
	if !info.IsPi {
		return
	}
	rpi001DefaultPassword(b)
	rpi002SSHIntentional(b)
	rpi003GPIO(b, info)
	rpi004Camera(b, info)
	rpi005Bluetooth(b, info)
	rpi006BootPermissions(b)
	rpi007AutoLogin(b)
	rpi008Swap(b)
	rpi009GPUMemory(b)
	rpi010HardwareInterfaces(b)
	rpi011Firmware(b)
	rpi012Throttle(b)
}

// rpi001DefaultPassword checks whether the 'pi' user still has the
// default password "raspberry". Reads /etc/shadow — needs root.
// On modern Pi OS the 'pi' user may not exist; that's a PASS.
func rpi001DefaultPassword(b *CheckBuilder) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		b.Skip("RPI-001", "Default 'pi' user password",
			"Cannot read /etc/shadow — run with sudo for this check", SeverityCritical)
		return
	}
	defer f.Close()

	var piHash string
	found := false
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), ":", 3)
		if len(parts) >= 2 && parts[0] == "pi" {
			piHash = parts[1]
			found = true
			break
		}
	}

	if !found {
		b.Pass("RPI-001", "Default 'pi' user password",
			"No 'pi' user account found (modern Pi OS or custom image)", SeverityCritical)
		return
	}
	if piHash == "" || piHash == "!" || piHash == "*" || piHash == "!!" {
		b.Pass("RPI-001", "Default 'pi' user password",
			"'pi' user account is locked or has no password set", SeverityCritical)
		return
	}

	// Verify via python3 crypt — Go's stdlib has no crypt(3) binding.
	// We use the same subprocess fallback the Python reference uses when
	// the crypt import fails.
	res := exec.Run("python3", "-c",
		fmt.Sprintf("import crypt; print(crypt.crypt('raspberry', %q))", piHash))
	switch {
	case res.Success() && strings.TrimSpace(res.Stdout) == piHash:
		b.Fail("RPI-001", "Default 'pi' user password",
			"CRITICAL: 'pi' user still has the default password 'raspberry'. "+
				"Change immediately: sudo passwd pi", SeverityCritical)
	case res.Success():
		b.Pass("RPI-001", "Default 'pi' user password",
			"'pi' user password has been changed from default", SeverityCritical)
	default:
		b.Warn("RPI-001", "Default 'pi' user password",
			"Could not verify if 'pi' password is default — verify manually: sudo passwd pi",
			SeverityCritical)
	}
}

func rpi002SSHIntentional(b *CheckBuilder) {
	res := exec.Run("systemctl", "is-active", "ssh")
	sshActive := res.Success() && strings.Contains(res.Stdout, "active")

	if !sshActive {
		b.Pass("RPI-002", "SSH enabled intentionally",
			"SSH service is not running", SeverityMedium)
		return
	}
	_, err1 := os.Stat("/boot/ssh")
	_, err2 := os.Stat("/boot/firmware/ssh")
	if err1 == nil || err2 == nil {
		b.Warn("RPI-002", "SSH enabled intentionally",
			"SSH is active via /boot/ssh trigger file — remove the file after setup "+
				"if you no longer need headless access, or ensure SSH is hardened",
			SeverityMedium)
	} else {
		b.Pass("RPI-002", "SSH enabled intentionally",
			"SSH is active (no trigger file — likely enabled via raspi-config)",
			SeverityMedium)
	}
}

func rpi003GPIO(b *CheckBuilder, info RPIInfo) {
	if !info.HasGPIO {
		b.Skip("RPI-003", "GPIO access restricted",
			"GPIO interface not detected", SeverityMedium)
		return
	}
	var issues []string
	if st, err := os.Stat("/sys/class/gpio/export"); err == nil {
		if st.Mode()&0o002 != 0 {
			issues = append(issues, "/sys/class/gpio/export is world-writable")
		}
	}
	if st, err := os.Stat("/dev/gpiochip0"); err == nil {
		mode := st.Mode().Perm()
		if mode&0o006 != 0 {
			issues = append(issues,
				fmt.Sprintf("/dev/gpiochip0 is world-accessible (mode %04o)", mode))
		}
	}
	if len(issues) > 0 {
		b.Warn("RPI-003", "GPIO access restricted",
			"GPIO hardware accessible to all users: "+strings.Join(issues, "; ")+
				". Restrict to gpio group only.",
			SeverityMedium)
	} else {
		b.Pass("RPI-003", "GPIO access restricted",
			"GPIO access is properly restricted", SeverityMedium)
	}
}

func rpi004Camera(b *CheckBuilder, info RPIInfo) {
	if info.HasCamera {
		b.Warn("RPI-004", "Camera interface enabled",
			"Camera interface (/dev/video0) is enabled. If not needed for your OpenClaw "+
				"deployment, disable via: sudo raspi-config → Interface Options → Camera",
			SeverityLow)
	} else {
		b.Pass("RPI-004", "Camera interface enabled",
			"Camera interface not detected (disabled or not connected)", SeverityLow)
	}
}

func rpi005Bluetooth(b *CheckBuilder, info RPIInfo) {
	if !info.HasBluetooth {
		b.Skip("RPI-005", "Bluetooth service running",
			"No Bluetooth hardware detected", SeverityMedium)
		return
	}
	res := exec.Run("systemctl", "is-active", "bluetooth")
	if res.Success() && strings.Contains(strings.TrimSpace(res.Stdout), "active") {
		b.Warn("RPI-005", "Bluetooth service running",
			"Bluetooth is active. If not needed, disable to reduce attack surface: "+
				"sudo systemctl disable --now bluetooth",
			SeverityMedium)
	} else {
		b.Pass("RPI-005", "Bluetooth service running",
			"Bluetooth hardware present but service is not active", SeverityMedium)
	}
}

func rpi006BootPermissions(b *CheckBuilder) {
	var bootPath string
	for _, d := range []string{"/boot/firmware", "/boot"} {
		if _, err := os.Stat(d); err == nil {
			bootPath = d
			break
		}
	}
	if bootPath == "" {
		b.Skip("RPI-006", "Boot partition file permissions",
			"Boot partition not found at expected paths", SeverityHigh)
		return
	}
	var issues []string
	for _, name := range []string{"config.txt", "cmdline.txt"} {
		path := filepath.Join(bootPath, name)
		if st, err := os.Stat(path); err == nil {
			if st.Mode()&0o002 != 0 {
				issues = append(issues, name+" is world-writable")
			}
		}
	}
	if len(issues) > 0 {
		b.Fail("RPI-006", "Boot partition file permissions",
			"Critical boot files are world-writable: "+strings.Join(issues, "; ")+
				fmt.Sprintf(". Fix: sudo chmod 644 %s/config.txt %s/cmdline.txt",
					bootPath, bootPath),
			SeverityHigh)
	} else {
		b.Pass("RPI-006", "Boot partition file permissions",
			fmt.Sprintf("Boot config files in %s have safe permissions", bootPath),
			SeverityHigh)
	}
}

func rpi007AutoLogin(b *CheckBuilder) {
	autologin := false

	// systemd getty autologin
	if f, err := os.ReadFile("/etc/systemd/system/getty@tty1.service.d/autologin.conf"); err == nil {
		if strings.Contains(strings.ToLower(string(f)), "autologin") {
			autologin = true
		}
	}

	// LightDM autologin
	if !autologin {
		if f, err := os.ReadFile("/etc/lightdm/lightdm.conf"); err == nil {
			for _, line := range strings.Split(string(f), "\n") {
				stripped := strings.TrimSpace(line)
				if strings.HasPrefix(stripped, "autologin-user=") && !strings.HasPrefix(stripped, "#") {
					user := strings.TrimSpace(strings.SplitN(stripped, "=", 2)[1])
					if user != "" {
						autologin = true
						break
					}
				}
			}
		}
	}

	if autologin {
		b.Fail("RPI-007", "Automatic console login disabled",
			"Auto-login is configured — anyone with physical access gets a shell. "+
				"Disable via: sudo raspi-config → System Options → Boot / Auto Login",
			SeverityHigh)
	} else {
		b.Pass("RPI-007", "Automatic console login disabled",
			"No automatic console login detected", SeverityHigh)
	}
}

func rpi008Swap(b *CheckBuilder) {
	res := exec.Run("free", "-m")
	if !res.Success() {
		return // not enough info — silently skip (matches Python behavior)
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if !strings.HasPrefix(line, "Swap:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			break
		}
		total, err := strconv.Atoi(parts[1])
		if err != nil {
			break
		}
		switch {
		case total == 0:
			b.Warn("RPI-008", "Swap space configured",
				"No swap space configured. On memory-constrained Pi hardware, this increases "+
					"OOM-kill risk for OpenClaw. Enable swap: sudo dphys-swapfile setup && sudo dphys-swapfile swapon",
				SeverityMedium)
		case total < 512:
			b.Warn("RPI-008", "Swap space configured",
				fmt.Sprintf("Only %dMB swap configured. Consider increasing to at least 512MB for "+
					"OpenClaw: edit /etc/dphys-swapfile, set CONF_SWAPSIZE=512", total),
				SeverityLow)
		default:
			b.Pass("RPI-008", "Swap space configured",
				fmt.Sprintf("%dMB swap configured", total), SeverityMedium)
		}
		break
	}
}

func rpi009GPUMemory(b *CheckBuilder) {
	// Find config.txt in firmware or legacy boot path
	var configPath string
	for _, d := range []string{"/boot/firmware", "/boot"} {
		p := filepath.Join(d, "config.txt")
		if _, err := os.Stat(p); err == nil {
			configPath = p
			break
		}
	}
	if configPath == "" {
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var gpuMem *int
	for _, line := range strings.Split(string(data), "\n") {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "gpu_mem=") && !strings.HasPrefix(stripped, "#") {
			if v, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(stripped, "=", 2)[1])); err == nil {
				gpuMem = &v
			}
			break
		}
	}

	var msg string
	var status Status
	switch {
	case gpuMem == nil:
		msg = "gpu_mem not set in config.txt (default 64-76MB). For headless OpenClaw servers, set gpu_mem=16 to free RAM."
		status = StatusWarn
	case *gpuMem > 64:
		msg = fmt.Sprintf("gpu_mem=%dMB is high for a headless server. Set gpu_mem=16 in config.txt to reclaim RAM for OpenClaw.", *gpuMem)
		status = StatusWarn
	default:
		msg = fmt.Sprintf("gpu_mem=%dMB (appropriate for server use)", *gpuMem)
		status = StatusPass
	}
	b.add("RPI-009", "GPU memory optimized for server", msg, status, SeverityLow)
}

func rpi010HardwareInterfaces(b *CheckBuilder) {
	var enabled []string
	_, i2c1 := os.Stat("/dev/i2c-1")
	_, i2c0 := os.Stat("/dev/i2c-0")
	if i2c1 == nil || i2c0 == nil {
		enabled = append(enabled, "I2C")
	}
	if _, err := os.Stat("/dev/spidev0.0"); err == nil {
		enabled = append(enabled, "SPI")
	}
	if len(enabled) > 0 {
		b.Warn("RPI-010", "Unnecessary hardware interfaces disabled",
			strings.Join(enabled, ", ")+" interface(s) enabled. If not needed for your "+
				"deployment, disable via: sudo raspi-config → Interface Options",
			SeverityLow)
	} else {
		b.Pass("RPI-010", "Unnecessary hardware interfaces disabled",
			"I2C and SPI interfaces are not enabled", SeverityLow)
	}
}

func rpi011Firmware(b *CheckBuilder) {
	if !commandExists("rpi-eeprom-update") {
		b.Skip("RPI-011", "Pi firmware up to date",
			"rpi-eeprom-update not installed (may be a Pi model without EEPROM)",
			SeverityMedium)
		return
	}
	res := exec.Run("rpi-eeprom-update")
	lower := strings.ToLower(res.Stdout)
	switch {
	case res.Success() && strings.Contains(lower, "update available"):
		b.Warn("RPI-011", "Pi firmware up to date",
			"Bootloader firmware update available. Run: sudo rpi-eeprom-update -a && sudo reboot",
			SeverityMedium)
	case res.Success():
		b.Pass("RPI-011", "Pi firmware up to date",
			"Bootloader firmware is up to date", SeverityMedium)
	default:
		b.Skip("RPI-011", "Pi firmware up to date",
			"rpi-eeprom-update returned an error — may need sudo", SeverityMedium)
	}
}

func rpi012Throttle(b *CheckBuilder) {
	if !commandExists("vcgencmd") {
		b.Skip("RPI-012", "No CPU throttling or power issues",
			"vcgencmd not available (may not be a Raspberry Pi)", SeverityMedium)
		return
	}
	res := exec.Run("vcgencmd", "get_throttled")
	if !res.Success() || !strings.Contains(res.Stdout, "=") {
		b.Skip("RPI-012", "No CPU throttling or power issues",
			"vcgencmd get_throttled failed", SeverityMedium)
		return
	}
	parts := strings.SplitN(strings.TrimSpace(res.Stdout), "=", 2)
	if len(parts) != 2 {
		b.Skip("RPI-012", "No CPU throttling or power issues",
			"Could not parse throttle status: "+res.Stdout, SeverityMedium)
		return
	}
	val, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 0, 64)
	if err != nil {
		b.Skip("RPI-012", "No CPU throttling or power issues",
			"Could not parse throttle status: "+res.Stdout, SeverityMedium)
		return
	}

	flags := map[int64]string{
		0x1:     "under-voltage detected NOW",
		0x2:     "ARM frequency capped NOW",
		0x4:     "currently throttled",
		0x8:     "soft temperature limit active",
		0x10000: "under-voltage occurred since boot",
		0x20000: "ARM frequency capped since boot",
		0x40000: "throttled since boot",
		0x80000: "soft temp limit occurred since boot",
	}
	var issues []string
	for bit, msg := range flags {
		if val&int64(bit) != 0 {
			issues = append(issues, msg)
		}
	}
	if len(issues) > 0 {
		b.Warn("RPI-012", "No CPU throttling or power issues",
			"Throttling detected: "+strings.Join(issues, "; ")+
				". Use an official power supply (5V/3A) and add a heatsink/fan.",
			SeverityMedium)
	} else {
		b.Pass("RPI-012", "No CPU throttling or power issues",
			"No throttling or power issues detected (0x0)", SeverityMedium)
	}
}

// commandExists returns true when the given command is on PATH.
func commandExists(name string) bool {
	res := exec.Run("which", name)
	return res.Success()
}
