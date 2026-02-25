package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// version is set at build time via -ldflags "-X main.version=x.y.z"
var version = "dev"

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiCyan   = "\033[0;36m"
	ansiGreen  = "\033[0;32m"
	ansiYellow = "\033[1;33m"
	ansiRed    = "\033[0;31m"
)

const (
	defaultURL          = "https://pulsewise.app/api/collect"
	versionCheckURL     = "https://pulsewise.app/collector/release/latest"
	collectionInterval  = 60 * time.Second
	updateCheckInterval = 6 * time.Hour
	configFilePath      = "/etc/pulsewise-collector/config"
	stateFilePath       = "/etc/pulsewise-collector/state"
	topProcessesCount   = 10

	launchdLabel    = "app.pulsewise.collector"
	launchdPlist    = "/Library/LaunchDaemons/app.pulsewise.collector.plist"
	systemdUnit     = "pulsewise-collector"
	systemdUnitFile = "/etc/systemd/system/pulsewise-collector.service"
	binaryPath      = "/usr/local/bin/pulsewise-collector"
	configDir       = "/etc/pulsewise-collector"
	macLogFile      = "/var/log/pulsewise-collector.log"
)

type Config struct {
	Token      string
	Hostname   string
	URL        string
	Interval   time.Duration
	Debug      bool
	AutoUpdate bool
}

type Metrics struct {
	Timestamp       time.Time       `json:"timestamp"`
	Token           string          `json:"token"`
	Hostname        string          `json:"hostname"`
	CollectorVersion  string     `json:"collector_version"`
	NextUpdateCheck   *time.Time `json:"next_update_check,omitempty"`
	Uptime            uint64     `json:"uptime"`
	System    SystemInfo      `json:"system"`
	LoadAvg   LoadMetrics     `json:"load_avg"`
	CPU       CPUMetrics      `json:"cpu"`
	Memory    MemoryMetrics   `json:"memory"`
	Swap      SwapMetrics     `json:"swap"`
	Disks     []DiskMetrics   `json:"disks"`
	DiskIO    DiskIOMetrics   `json:"disk_io"`
	Network   *NetworkMetrics `json:"network"`
	Processes       []ProcessInfo    `json:"processes"`
	TCP             *TCPStats        `json:"tcp,omitempty"`
	FileDescriptors *FileDescriptors `json:"file_descriptors,omitempty"`
}

type SystemInfo struct {
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	KernelArch      string `json:"kernel_arch"`
	Virtualization  string `json:"virtualization"`
	CPUModel        string `json:"cpu_model"`
}

type LoadMetrics struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type CPUMetrics struct {
	Percent float64   `json:"percent"`
	Iowait  float64   `json:"iowait_percent"`
	PerCore []float64 `json:"per_core"`
	Count   int       `json:"core_count"`
}

type TCPStats struct {
	Established int `json:"established"`
	TimeWait    int `json:"time_wait"`
	CloseWait   int `json:"close_wait"`
	Listen      int `json:"listen"`
	MaxTimeWait int `json:"max_time_wait,omitempty"` // Linux only
}

type FileDescriptors struct {
	Used int `json:"used"`
	Max  int `json:"max"`
}

type MemoryMetrics struct {
	Total       uint64  `json:"total"`
	Available   uint64  `json:"available"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"used_percent"`
}

type SwapMetrics struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type DiskMetrics struct {
	Mountpoint  string  `json:"mountpoint"`
	Device      string  `json:"device"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Free        uint64  `json:"free"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"used_percent"`
}

type DiskIOMetrics struct {
	ReadBytes      uint64 `json:"read_bytes"`
	WriteBytes     uint64 `json:"write_bytes"`
	ReadCount      uint64 `json:"read_count"`
	WriteCount     uint64 `json:"write_count"`
	IopsInProgress uint64 `json:"iops_in_progress"`
}

type NetworkMetrics struct {
	BytesSentPerSec   float64 `json:"bytes_sent_per_sec"`
	BytesRecvPerSec   float64 `json:"bytes_recv_per_sec"`
	PacketsSentPerSec float64 `json:"packets_sent_per_sec"`
	PacketsRecvPerSec float64 `json:"packets_recv_per_sec"`
}

type networkSnapshot struct {
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	Time        time.Time
}

type ProcessInfo struct {
	PID         int32   `json:"pid"`
	Name        string  `json:"name"`
	Command     string  `json:"command"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float32 `json:"mem_percent"`
	CPUTime     float64 `json:"cpu_time"`
	MemoryBytes uint64  `json:"memory_bytes"`
}

var prevNet *networkSnapshot

// nextUpdateCheck is set by the auto-updater goroutine so it can be included
// in every pulse. Nil when auto-update is disabled.
var nextUpdateCheck *time.Time

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			runVersionCommand()
			return
		case "update":
			runUpdateCommand()
			return
		case "status":
			runStatusCommand()
			return
		case "uninstall":
			runUninstallCommand()
			return
		case "dump":
			runDumpCommand()
			return
		}
	}

	noAutoUpdate := flag.Bool("no-auto-update", false, "disable automatic updates")
	flag.Parse()

	config := loadConfig()
	if *noAutoUpdate {
		config.AutoUpdate = false
	}

	log.Printf("Starting Pulsewise collector (v%s)...", version)
	log.Printf("Hostname: %s", config.Hostname)
	log.Printf("Target URL: %s", config.URL)
	log.Printf("Collection interval: %v", config.Interval)
	if config.AutoUpdate {
		log.Printf("Auto-update: enabled")
	} else {
		log.Printf("Auto-update: disabled")
	}

	if config.AutoUpdate {
		go runAutoUpdater(config)
	} else {
		nextUpdateCheck = nil
	}

	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	collectAndSend(config)

	for range ticker.C {
		collectAndSend(config)
	}
}

// ─────────────────────────────────────────────────────────────
// Subcommands
// ─────────────────────────────────────────────────────────────

func runVersionCommand() {
	fmt.Printf("\n  %spulsewise-collector%s\n", ansiBold, ansiReset)
	fmt.Printf("  %s%sv%s%s\n\n", ansiBold, ansiCyan, version, ansiReset)

	fmt.Printf("  %sChecking for updates...%s ", ansiDim, ansiReset)
	latest, err := fetchLatestVersion()
	if err != nil {
		fmt.Printf("%s(update check failed: %v)%s\n\n", ansiDim, err, ansiReset)
		return
	}

	if latest == version {
		fmt.Printf("%sYou are on the latest version.%s\n\n", ansiGreen, ansiReset)
	} else {
		fmt.Printf("%sv%s is available%s\n", ansiYellow, latest, ansiReset)
		fmt.Printf("  %sRun 'pulsewise-collector update' to upgrade.%s\n\n", ansiDim, ansiReset)
	}
}

func runUpdateCommand() {
	if os.Getuid() != 0 {
		reexecWithSudo()
		return
	}

	fmt.Printf("\n  %spulsewise-collector%s\n", ansiBold, ansiReset)
	fmt.Printf("  %s%sv%s%s\n\n", ansiBold, ansiCyan, version, ansiReset)

	fmt.Printf("  %sChecking for updates...%s ", ansiDim, ansiReset)
	latest, err := fetchLatestVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%supdate check failed: %v%s\n\n", ansiRed, err, ansiReset)
		os.Exit(1)
	}

	if latest == version {
		fmt.Printf("%sAlready on the latest version.%s\n\n", ansiGreen, ansiReset)
		return
	}

	fmt.Printf("%sv%s is available%s\n\n", ansiYellow, latest, ansiReset)
	fmt.Printf("  %sDownloading...%s ", ansiDim, ansiReset)

	if err := downloadAndReplace(); err != nil {
		fmt.Fprintf(os.Stderr, "\n  %sUpdate failed: %v%s\n\n", ansiRed, err, ansiReset)
		os.Exit(1)
	}

	fmt.Printf("%sDone.%s\n", ansiGreen, ansiReset)
	fmt.Printf("  Successfully updated to %sv%s%s.\n\n", ansiCyan, latest, ansiReset)

	restartService()
}

func restartService() {
	fmt.Printf("  %sRestarting service...%s ", ansiDim, ansiReset)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "restart", systemdUnit)
	case "darwin":
		cmd = exec.Command("launchctl", "kickstart", "-k", "system/"+launchdLabel)
	default:
		fmt.Printf("%snot supported on this platform%s\n\n", ansiDim, ansiReset)
		return
	}

	if err := cmd.Run(); err != nil {
		fmt.Printf("%sfailed%s (%v)\n", ansiRed, ansiReset, err)
		fmt.Printf("  %sRestart manually: systemctl restart %s%s\n\n", ansiDim, systemdUnit, ansiReset)
		return
	}

	fmt.Printf("%sdone%s\n\n", ansiGreen, ansiReset)
}

func runDumpCommand() {
	if os.Getuid() != 0 {
		reexecWithSudo()
		return
	}

	config := loadConfig()

	metrics, err := collectMetrics(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError collecting metrics: %v%s\n", ansiRed, err, ansiReset)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError marshalling metrics: %v%s\n", ansiRed, err, ansiReset)
		os.Exit(1)
	}

	fmt.Println(string(out))
}

func reexecWithSudo() {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cmd := exec.Command("sudo", append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func runStatusCommand() {
	if os.Getuid() != 0 {
		reexecWithSudo()
		return
	}

	label := func(s string) string { return fmt.Sprintf("  %s%-16s%s", ansiDim, s, ansiReset) }

	fmt.Printf("\n%spulsewise-collector%s v%s\n\n", ansiBold, ansiReset, version)

	// Config
	token, hostname, url, _, autoUpdate, err := loadConfigFromFile()
	if err != nil {
		fmt.Printf("%s  Not configured — %v\n\n", ansiRed, ansiReset)
	} else {
		maskedToken := token
		if len(token) >= 8 {
			maskedToken = token[:4] + "..." + token[len(token)-4:]
		} else {
			maskedToken = "****"
		}
		autoUpdateStr := ansiGreen + "enabled" + ansiReset
		if !autoUpdate {
			autoUpdateStr = ansiDim + "disabled" + ansiReset
		}
		fmt.Printf("%sCollector%s\n", ansiBold, ansiReset)
		fmt.Printf("%s %s\n", label("Hostname"), hostname)
		fmt.Printf("%s %s\n", label("Token"), maskedToken)
		fmt.Printf("%s %s\n", label("API endpoint"), url)
		fmt.Printf("%s %s\n", label("Interval"), collectionInterval)
		fmt.Printf("%s %s\n", label("Auto-update"), autoUpdateStr)
		fmt.Println()
	}

	// Service status
	fmt.Printf("%sService%s\n", ansiBold, ansiReset)
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("systemctl", "is-active", systemdUnit).Output()
		state := strings.TrimSpace(string(out))
		if err == nil && state == "active" {
			fmt.Printf("%s %srunning%s (systemd)\n", label("Status"), ansiGreen, ansiReset)
		} else {
			fmt.Printf("%s %sstopped%s (systemd)\n", label("Status"), ansiRed, ansiReset)
		}
	case "darwin":
		err := exec.Command("launchctl", "list", launchdLabel).Run()
		if err == nil {
			fmt.Printf("%s %srunning%s (launchd)\n", label("Status"), ansiGreen, ansiReset)
		} else {
			fmt.Printf("%s %sstopped%s (launchd)\n", label("Status"), ansiRed, ansiReset)
		}
	default:
		fmt.Printf("%s unknown platform\n", label("Status"))
	}

	// Last pulse
	if t, err := readLastPulse(); err == nil {
		ago := time.Since(t).Round(time.Second)
		fmt.Printf("%s %s  %s(%s ago)%s\n", label("Last pulse"), t.Format("2006-01-02 15:04:05"), ansiDim, ago, ansiReset)
	} else {
		fmt.Printf("%s never\n", label("Last pulse"))
	}
	fmt.Println()
}

func runUninstallCommand() {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "%sError:%s uninstall must be run as root (try sudo pulsewise-collector uninstall)\n", ansiRed, ansiReset)
		os.Exit(1)
	}

	selfPath, _ := os.Executable()
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	fmt.Printf("\n%sUninstall pulsewise-collector%s\n\n", ansiBold, ansiReset)
	fmt.Printf("  %sThe following will be removed:%s\n", ansiDim, ansiReset)

	switch runtime.GOOS {
	case "linux":
		fmt.Printf("    Service   /etc/systemd/system/%s.service\n", systemdUnit)
	case "darwin":
		fmt.Printf("    Service   %s\n", launchdPlist)
		fmt.Printf("    Logs      %s\n", macLogFile)
	}
	fmt.Printf("    Binary    %s\n", selfPath)
	fmt.Printf("    Config    %s/\n", configDir)
	fmt.Println()

	fmt.Printf("  %sAre you sure?%s [y/N]: ", ansiYellow, ansiReset)
	var reply string
	fmt.Scanln(&reply)
	if strings.ToLower(strings.TrimSpace(reply)) != "y" {
		fmt.Println("\n  Cancelled.")
		return
	}
	fmt.Println()

	step := func(label, path string, fn func() error) {
		fmt.Printf("  %-28s", label+"...")
		if err := fn(); err != nil {
			fmt.Printf("%sfailed%s (%v)\n", ansiRed, ansiReset, err)
		} else {
			fmt.Printf("%sdone%s\n", ansiGreen, ansiReset)
		}
	}

	switch runtime.GOOS {
	case "linux":
		step("Stopping service", "", func() error {
			exec.Command("systemctl", "stop", systemdUnit).Run()
			return nil
		})
		step("Disabling service", "", func() error {
			exec.Command("systemctl", "disable", "--quiet", systemdUnit).Run()
			return nil
		})
		step("Removing unit file", systemdUnitFile, func() error {
			err := os.Remove(systemdUnitFile)
			exec.Command("systemctl", "daemon-reload").Run()
			return err
		})
	case "darwin":
		step("Stopping service", "", func() error {
			exec.Command("launchctl", "bootout", "system", launchdPlist).Run()
			return nil
		})
		step("Removing plist", launchdPlist, func() error {
			return os.Remove(launchdPlist)
		})
		step("Removing log file", macLogFile, func() error {
			err := os.Remove(macLogFile)
			if os.IsNotExist(err) {
				return nil
			}
			return err
		})
	}

	step("Removing config dir", configDir, func() error {
		return os.RemoveAll(configDir)
	})

	// Remove the binary last — the process keeps running from the
	// already-mapped memory pages until os.Exit, so this is safe.
	step("Removing binary", selfPath, func() error {
		return os.Remove(selfPath)
	})

	fmt.Printf("\n  %sPulsewise Collector has been uninstalled.%s\n\n", ansiGreen, ansiReset)
}

// ─────────────────────────────────────────────────────────────
// State file (last pulse timestamp)
// ─────────────────────────────────────────────────────────────

func resolveStateFilePath() string {
	if _, err := os.Stat(filepath.Dir(stateFilePath)); err == nil {
		return stateFilePath
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".config", "pulsewise-collector", "state")
}

func writeLastPulse() {
	path := resolveStateFilePath()
	if path == "" {
		return
	}
	_ = os.WriteFile(path, []byte(fmt.Sprintf("%d", time.Now().Unix())), 0644)
}

func readLastPulse() (time.Time, error) {
	path := resolveStateFilePath()
	if path == "" {
		return time.Time{}, fmt.Errorf("no state path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var ts int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &ts); err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts, 0), nil
}

// ─────────────────────────────────────────────────────────────
// Auto-update
// ─────────────────────────────────────────────────────────────

type latestRelease struct {
	Version string `json:"version"`
}

func runAutoUpdater(config *Config) {
	t := time.Now().UTC().Add(30 * time.Second)
	nextUpdateCheck = &t

	time.Sleep(30 * time.Second)
	checkAndUpdate(config)

	ticker := time.NewTicker(updateCheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		checkAndUpdate(config)
	}
}

func scheduleNextUpdateCheck() {
	t := time.Now().UTC().Add(updateCheckInterval)
	nextUpdateCheck = &t
}

func checkAndUpdate(config *Config) {
	latest, err := fetchLatestVersion()
	if err != nil {
		if config.Debug {
			log.Printf("[DEBUG] Update check failed: %v", err)
		}
		scheduleNextUpdateCheck()
		return
	}

	if latest == version {
		if config.Debug {
			log.Printf("[DEBUG] Already on latest version %s", version)
		}
		scheduleNextUpdateCheck()
		return
	}

	log.Printf("Update available: v%s → v%s. Downloading...", version, latest)

	if err := downloadAndReplace(); err != nil {
		log.Printf("Auto-update failed: %v", err)
		scheduleNextUpdateCheck()
		return
	}

	log.Printf("Update successful. Restarting service...")
	switch runtime.GOOS {
	case "linux":
		exec.Command("systemctl", "restart", systemdUnit).Run()
	case "darwin":
		exec.Command("launchctl", "kickstart", "-k", "system/"+launchdLabel).Run()
	default:
		execSelf()
	}
}

func fetchLatestVersion() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(versionCheckURL)
	if err != nil {
		return "", fmt.Errorf("version check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("version check returned status %d", resp.StatusCode)
	}

	var release latestRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse version response: %w", err)
	}

	if release.Version == "" {
		return "", fmt.Errorf("empty version in response")
	}

	return release.Version, nil
}

func downloadAndReplace() error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	downloadURL := fmt.Sprintf("https://pulsewise.app/collector/download/%s-%s", goos, goarch)

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Create temp file in the same directory so os.Rename is atomic (same filesystem).
	tmpFile, err := os.CreateTemp(filepath.Dir(selfPath), ".pulsewise-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	cleanup := func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		cleanup()
		return fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cleanup()
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		cleanup()
		return fmt.Errorf("failed to write downloaded binary: %w", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	if err := os.Rename(tmpPath, selfPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}

// execSelf replaces the current process image with the newly downloaded binary.
// If exec fails, we exit and let the service manager restart the process.
func execSelf() {
	self, err := os.Executable()
	if err != nil {
		log.Printf("Failed to get executable path for restart: %v — exiting for service manager restart", err)
		os.Exit(0)
	}

	if err := syscall.Exec(self, os.Args, os.Environ()); err != nil {
		log.Printf("Failed to re-exec after update: %v — exiting for service manager restart", err)
		os.Exit(0)
	}
}

// ─────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────

func loadConfig() *Config {
	token, hostname, url, debug, autoUpdate, err := loadConfigFromFile()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	return &Config{
		Token:      token,
		Hostname:   hostname,
		URL:        url,
		Interval:   collectionInterval,
		Debug:      debug,
		AutoUpdate: autoUpdate,
	}
}

func loadConfigFromFile() (string, string, string, bool, bool, error) {
	configPath := configFilePath

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			localConfigPath := filepath.Join(homeDir, ".config", "pulsewise-collector", "config")
			if _, err := os.Stat(localConfigPath); err == nil {
				configPath = localConfigPath
			}
		}
	}

	file, err := os.Open(configPath)
	if err != nil {
		return "", "", "", false, false, fmt.Errorf("config file not found at %s: %w", configPath, err)
	}
	defer file.Close()

	var token, hostname, url string
	var debug bool
	autoUpdate := true

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "TOKEN=") {
			token = strings.TrimPrefix(line, "TOKEN=")
			token = strings.Trim(token, `"'`)
		}
		if strings.HasPrefix(line, "HOSTNAME=") {
			hostname = strings.TrimPrefix(line, "HOSTNAME=")
			hostname = strings.Trim(hostname, `"'`)
		}
		if strings.HasPrefix(line, "URL=") {
			url = strings.TrimPrefix(line, "URL=")
			url = strings.Trim(url, `"'`)
		}
		if strings.HasPrefix(line, "DEBUG=") {
			val := strings.TrimPrefix(line, "DEBUG=")
			val = strings.Trim(val, `"'`)
			debug = val == "true" || val == "1"
		}
		if strings.HasPrefix(line, "AUTO_UPDATE=") {
			val := strings.TrimPrefix(line, "AUTO_UPDATE=")
			val = strings.Trim(val, `"'`)
			autoUpdate = val != "false" && val != "0"
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", false, false, fmt.Errorf("error reading config file: %w", err)
	}

	if token == "" {
		return "", "", "", false, false, fmt.Errorf("TOKEN not found in config file")
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	if url == "" {
		url = defaultURL
	}

	return token, hostname, url, debug, autoUpdate, nil
}

func collectAndSend(config *Config) {
	metrics, err := collectMetrics(config)
	if err != nil {
		log.Printf("Error collecting metrics: %v", err)
		return
	}

	if err := sendMetrics(config, metrics); err != nil {
		log.Printf("Error sending metrics: %v", err)
		return
	}

	writeLastPulse()
	log.Printf("Successfully sent metrics at %s", time.Now().Format(time.RFC3339))
}

// virtualFSTypes are filesystem types that should be excluded from disk
// reporting — pseudo, read-only, or kernel-managed mounts that aren't
// real storage (snap loop devices, tmpfs, container overlays, etc.).
var virtualFSTypes = map[string]bool{
	"squashfs":    true, // snap packages — always 100% full
	"tmpfs":       true,
	"devtmpfs":    true,
	"ramfs":       true,
	"overlay":     true,
	"overlayfs":   true,
	"proc":        true,
	"sysfs":       true,
	"devfs":       true,
	"cgroup":      true,
	"cgroup2":     true,
	"pstore":      true,
	"efivarfs":    true,
	"bpf":         true,
	"fusectl":     true,
	"hugetlbfs":   true,
	"mqueue":      true,
	"debugfs":     true,
	"tracefs":     true,
	"securityfs":  true,
	"configfs":    true,
	"autofs":      true,
}

func isVirtualFS(fstype, device string) bool {
	if virtualFSTypes[fstype] {
		return true
	}
	// Loop devices back read-only images (snaps, ISOs, etc.)
	if strings.HasPrefix(device, "/dev/loop") {
		return true
	}
	return false
}

func collectMetrics(config *Config) (*Metrics, error) {
	metrics := &Metrics{
		Timestamp:        time.Now().UTC(),
		Token:            config.Token,
		Hostname:         config.Hostname,
		CollectorVersion: version,
		NextUpdateCheck:  nextUpdateCheck,
	}

	// Uptime
	uptime, err := host.Uptime()
	if err != nil {
		log.Printf("Warning: Failed to get uptime: %v", err)
	} else {
		metrics.Uptime = uptime
	}

	// System info
	hostInfo, err := host.Info()
	if err != nil {
		log.Printf("Warning: Failed to get host info: %v", err)
	} else {
		metrics.System = SystemInfo{
			OS:              hostInfo.OS,
			Platform:        hostInfo.Platform,
			PlatformVersion: hostInfo.PlatformVersion,
			KernelVersion:   hostInfo.KernelVersion,
			KernelArch:      hostInfo.KernelArch,
			Virtualization:  hostInfo.VirtualizationSystem,
		}
	}

	cpuInfo, err := cpu.Info()
	if err != nil {
		log.Printf("Warning: Failed to get CPU info: %v", err)
	} else if len(cpuInfo) > 0 {
		metrics.System.CPUModel = cpuInfo[0].ModelName
	}

	// Load average
	loadAvg, err := load.Avg()
	if err != nil {
		log.Printf("Warning: Failed to get load average: %v", err)
	} else {
		metrics.LoadAvg = LoadMetrics{
			Load1:  loadAvg.Load1,
			Load5:  loadAvg.Load5,
			Load15: loadAvg.Load15,
		}
	}

	// CPU — single sample with percpu=true, then average for the total.
	// Calling cpu.Percent twice with separate 1s windows can produce
	// wildly inconsistent totals vs per-core values.
	cpuPerCore, err := cpu.Percent(time.Second, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU percent: %w", err)
	}
	metrics.CPU.PerCore = cpuPerCore
	if len(cpuPerCore) > 0 {
		var sum float64
		for _, p := range cpuPerCore {
			sum += p
		}
		metrics.CPU.Percent = sum / float64(len(cpuPerCore))
	}

	cpuTimes, err := cpu.Times(false)
	if err == nil && len(cpuTimes) > 0 {
		t := cpuTimes[0]
		total := t.User + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal + t.Nice + t.Guest + t.GuestNice
		if total > 0 {
			metrics.CPU.Iowait = (t.Iowait / total) * 100
		}
	}

	cpuCount, err := cpu.Counts(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU count: %w", err)
	}
	metrics.CPU.Count = cpuCount

	// Memory
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}
	metrics.Memory = MemoryMetrics{
		Total:       memInfo.Total,
		Available:   memInfo.Available,
		Used:        memInfo.Used,
		UsedPercent: memInfo.UsedPercent,
	}

	// Swap
	swapInfo, err := mem.SwapMemory()
	if err != nil {
		log.Printf("Warning: Failed to get swap info: %v", err)
	} else {
		metrics.Swap = SwapMetrics{
			Total:       swapInfo.Total,
			Used:        swapInfo.Used,
			Free:        swapInfo.Free,
			UsedPercent: swapInfo.UsedPercent,
		}
	}

	// Disk usage per mount point
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk partitions: %w", err)
	}
	for _, p := range partitions {
		if isVirtualFS(p.Fstype, p.Device) {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		if usage.Total == 0 {
			continue
		}
		metrics.Disks = append(metrics.Disks, DiskMetrics{
			Mountpoint:  p.Mountpoint,
			Device:      p.Device,
			Fstype:      p.Fstype,
			Total:       usage.Total,
			Free:        usage.Free,
			Used:        usage.Used,
			UsedPercent: usage.UsedPercent,
		})
	}

	// Disk I/O (aggregate across all devices)
	ioCounters, err := disk.IOCounters()
	if err != nil {
		log.Printf("Warning: Failed to get disk I/O: %v", err)
	} else {
		var totalRead, totalWrite, totalReadCount, totalWriteCount, totalIops uint64
		for _, io := range ioCounters {
			totalRead += io.ReadBytes
			totalWrite += io.WriteBytes
			totalReadCount += io.ReadCount
			totalWriteCount += io.WriteCount
			totalIops += io.IopsInProgress
		}
		metrics.DiskIO = DiskIOMetrics{
			ReadBytes:      totalRead,
			WriteBytes:     totalWrite,
			ReadCount:      totalReadCount,
			WriteCount:     totalWriteCount,
			IopsInProgress: totalIops,
		}
	}

	// Network (per-second rates)
	netStats, err := net.IOCounters(false)
	if err != nil {
		log.Printf("Warning: Failed to get network stats: %v", err)
	} else if len(netStats) > 0 {
		var totalSent, totalRecv, totalPacketsSent, totalPacketsRecv uint64
		for _, stat := range netStats {
			totalSent += stat.BytesSent
			totalRecv += stat.BytesRecv
			totalPacketsSent += stat.PacketsSent
			totalPacketsRecv += stat.PacketsRecv
		}

		now := time.Now()
		current := &networkSnapshot{
			BytesSent:   totalSent,
			BytesRecv:   totalRecv,
			PacketsSent: totalPacketsSent,
			PacketsRecv: totalPacketsRecv,
			Time:        now,
		}

		if prevNet != nil &&
			totalSent >= prevNet.BytesSent &&
			totalRecv >= prevNet.BytesRecv {
			elapsed := now.Sub(prevNet.Time).Seconds()
			if elapsed > 0 {
				metrics.Network = &NetworkMetrics{
					BytesSentPerSec:   float64(totalSent-prevNet.BytesSent) / elapsed,
					BytesRecvPerSec:   float64(totalRecv-prevNet.BytesRecv) / elapsed,
					PacketsSentPerSec: float64(totalPacketsSent-prevNet.PacketsSent) / elapsed,
					PacketsRecvPerSec: float64(totalPacketsRecv-prevNet.PacketsRecv) / elapsed,
				}
			}
		}

		prevNet = current
	}

	// Top processes
	processes, err := collectTopProcesses()
	if err != nil {
		log.Printf("Warning: Failed to collect process info: %v", err)
		metrics.Processes = []ProcessInfo{}
	} else {
		metrics.Processes = processes
	}

	metrics.TCP = collectTCPStats()
	metrics.FileDescriptors = collectFileDescriptors()

	return metrics, nil
}

func collectTCPStats() *TCPStats {
	conns, err := net.Connections("tcp")
	if err != nil {
		return nil
	}
	conns6, _ := net.Connections("tcp6")
	conns = append(conns, conns6...)

	stats := &TCPStats{}
	for _, c := range conns {
		switch c.Status {
		case "ESTABLISHED":
			stats.Established++
		case "TIME_WAIT":
			stats.TimeWait++
		case "CLOSE_WAIT":
			stats.CloseWait++
		case "LISTEN":
			stats.Listen++
		}
	}

	// Linux: include the system TIME_WAIT bucket limit for context
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_max_tw_buckets"); err == nil {
			if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				stats.MaxTimeWait = v
			}
		}
	}

	return stats
}

func collectFileDescriptors() *FileDescriptors {
	switch runtime.GOOS {
	case "linux":
		// /proc/sys/fs/file-nr: allocated  unused  max
		data, err := os.ReadFile("/proc/sys/fs/file-nr")
		if err != nil {
			return nil
		}
		fields := strings.Fields(string(data))
		if len(fields) < 3 {
			return nil
		}
		used, err1 := strconv.Atoi(fields[0])
		max, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil
		}
		return &FileDescriptors{Used: used, Max: max}

	case "darwin":
		openOut, err1 := exec.Command("sysctl", "-n", "kern.openfiles").Output()
		maxOut, err2 := exec.Command("sysctl", "-n", "kern.maxfiles").Output()
		if err1 != nil || err2 != nil {
			return nil
		}
		used, err1 := strconv.Atoi(strings.TrimSpace(string(openOut)))
		max, err2 := strconv.Atoi(strings.TrimSpace(string(maxOut)))
		if err1 != nil || err2 != nil {
			return nil
		}
		return &FileDescriptors{Used: used, Max: max}
	}

	return nil
}

func collectTopProcesses() ([]ProcessInfo, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("failed to get process list: %w", err)
	}

	type procData struct {
		proc       *process.Process
		pid        int32
		name       string
		cmdline    string
		memPercent float32
		memInfo    *process.MemoryInfoStat
		cpuTime    float64
	}

	var processes []procData

	for _, pid := range pids {
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		_, err = proc.CPUPercent()
		if err != nil {
			continue
		}

		name, err := proc.Name()
		if err != nil {
			name = "unknown"
		}

		cmdline, err := proc.Cmdline()
		if err != nil {
			cmdline = name
		}
		if len(cmdline) > 200 {
			cmdline = cmdline[:200] + "..."
		}

		memPercent, err := proc.MemoryPercent()
		if err != nil {
			continue
		}

		memInfo, err := proc.MemoryInfo()
		if err != nil {
			continue
		}

		cpuTimes, err := proc.Times()
		if err != nil {
			continue
		}
		cpuTime := cpuTimes.User + cpuTimes.System

		processes = append(processes, procData{
			proc:       proc,
			pid:        pid,
			name:       name,
			cmdline:    cmdline,
			memPercent: memPercent,
			memInfo:    memInfo,
			cpuTime:    cpuTime,
		})
	}

	time.Sleep(time.Millisecond * 200)

	var processList []ProcessInfo
	for _, p := range processes {
		cpuPercent, err := p.proc.CPUPercent()
		if err != nil {
			continue
		}

		processList = append(processList, ProcessInfo{
			PID:         p.pid,
			Name:        p.name,
			Command:     p.cmdline,
			CPUPercent:  cpuPercent,
			MemPercent:  p.memPercent,
			CPUTime:     p.cpuTime,
			MemoryBytes: p.memInfo.RSS,
		})
	}

	// Sort by CPU usage (descending) and take top N
	for i := 0; i < len(processList) && i < topProcessesCount; i++ {
		maxIdx := i
		for j := i + 1; j < len(processList); j++ {
			if processList[j].CPUPercent > processList[maxIdx].CPUPercent {
				maxIdx = j
			}
		}
		if maxIdx != i {
			processList[i], processList[maxIdx] = processList[maxIdx], processList[i]
		}
	}

	if len(processList) > topProcessesCount {
		return processList[:topProcessesCount], nil
	}

	return processList, nil
}

func sendMetrics(config *Config, metrics *Metrics) error {
	jsonData, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	req, err := http.NewRequest("POST", config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.Token)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if config.Debug {
		log.Printf("[DEBUG] Response %d: %s", resp.StatusCode, string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d — %s", resp.StatusCode, string(body))
	}

	return nil
}
