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
	defaultURL          = "https://pulsewise.app/api/collect"
	versionCheckURL     = "https://pulsewise.app/collector/release/latest"
	collectionInterval  = 30 * time.Second
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
	Processes []ProcessInfo   `json:"processes"`
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
	PerCore []float64 `json:"per_core"`
	Count   int       `json:"core_count"`
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
		}
	}

	noAutoUpdate := flag.Bool("no-auto-update", false, "disable automatic updates")
	flag.Parse()

	config := loadConfig()
	config.AutoUpdate = !*noAutoUpdate

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
	fmt.Printf("pulsewise-collector v%s\n\n", version)

	fmt.Print("Checking for updates... ")
	latest, err := fetchLatestVersion()
	if err != nil {
		fmt.Printf("(update check failed: %v)\n", err)
		return
	}

	if latest == version {
		fmt.Println("You are on the latest version.")
	} else {
		fmt.Printf("v%s is available.\n", latest)
		fmt.Println("Run 'pulsewise-collector update' to upgrade.")
	}
}

func runUpdateCommand() {
	fmt.Printf("pulsewise-collector v%s\n\n", version)

	fmt.Print("Checking for updates... ")
	latest, err := fetchLatestVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
		os.Exit(1)
	}

	if latest == version {
		fmt.Printf("Already on the latest version (v%s).\n", version)
		return
	}

	fmt.Printf("v%s is available.\n\n", latest)
	fmt.Print("Downloading... ")

	if err := downloadAndReplace(); err != nil {
		fmt.Fprintf(os.Stderr, "\nUpdate failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Done.\nSuccessfully updated to v%s.\n", latest)
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

	const (
		bold  = "\033[1m"
		dim   = "\033[2m"
		green = "\033[0;32m"
		red   = "\033[0;31m"
		nc    = "\033[0m"
	)

	label := func(s string) string { return fmt.Sprintf("  %s%-16s%s", dim, s, nc) }

	fmt.Printf("\n%spulsewise-collector%s v%s\n\n", bold, nc, version)

	// Config
	token, hostname, url, _, err := loadConfigFromFile()
	if err != nil {
		fmt.Printf("%s  Not configured — %v\n\n", red, nc)
	} else {
		maskedToken := token
		if len(token) >= 8 {
			maskedToken = token[:4] + "..." + token[len(token)-4:]
		} else {
			maskedToken = "****"
		}
		fmt.Printf("%sCollector%s\n", bold, nc)
		fmt.Printf("%s %s\n", label("Hostname"), hostname)
		fmt.Printf("%s %s\n", label("Token"), maskedToken)
		fmt.Printf("%s %s\n", label("API endpoint"), url)
		fmt.Printf("%s %s\n", label("Interval"), collectionInterval)
		fmt.Println()
	}

	// Service status
	fmt.Printf("%sService%s\n", bold, nc)
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("systemctl", "is-active", systemdUnit).Output()
		state := strings.TrimSpace(string(out))
		if err == nil && state == "active" {
			fmt.Printf("%s %srunning%s (systemd)\n", label("Status"), green, nc)
		} else {
			fmt.Printf("%s %sstopped%s (systemd)\n", label("Status"), red, nc)
		}
	case "darwin":
		err := exec.Command("launchctl", "list", launchdLabel).Run()
		if err == nil {
			fmt.Printf("%s %srunning%s (launchd)\n", label("Status"), green, nc)
		} else {
			fmt.Printf("%s %sstopped%s (launchd)\n", label("Status"), red, nc)
		}
	default:
		fmt.Printf("%s unknown platform\n", label("Status"))
	}

	// Last pulse
	if t, err := readLastPulse(); err == nil {
		ago := time.Since(t).Round(time.Second)
		fmt.Printf("%s %s  %s(%s ago)%s\n", label("Last pulse"), t.Format("2006-01-02 15:04:05"), dim, ago, nc)
	} else {
		fmt.Printf("%s never\n", label("Last pulse"))
	}
	fmt.Println()
}

func runUninstallCommand() {
	const (
		bold   = "\033[1m"
		dim    = "\033[2m"
		green  = "\033[0;32m"
		red    = "\033[0;31m"
		yellow = "\033[1;33m"
		nc     = "\033[0m"
	)

	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "%sError:%s uninstall must be run as root (try sudo pulsewise-collector uninstall)\n", red, nc)
		os.Exit(1)
	}

	selfPath, _ := os.Executable()
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	fmt.Printf("\n%sUninstall pulsewise-collector%s\n\n", bold, nc)
	fmt.Printf("  %sThe following will be removed:%s\n", dim, nc)

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

	fmt.Printf("  %sAre you sure?%s [y/N]: ", yellow, nc)
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
			fmt.Printf("%sfailed%s (%v)\n", red, nc, err)
		} else {
			fmt.Printf("%sdone%s\n", green, nc)
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

	fmt.Printf("\n  %sPulsewise Collector has been uninstalled.%s\n\n", green, nc)
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

	log.Printf("Update successful. Restarting...")
	execSelf()
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
	token, hostname, url, debug, err := loadConfigFromFile()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	return &Config{
		Token:    token,
		Hostname: hostname,
		URL:      url,
		Interval: collectionInterval,
		Debug:    debug,
	}
}

func loadConfigFromFile() (string, string, string, bool, error) {
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
		return "", "", "", false, fmt.Errorf("config file not found at %s: %w", configPath, err)
	}
	defer file.Close()

	var token, hostname, url string
	var debug bool

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
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", false, fmt.Errorf("error reading config file: %w", err)
	}

	if token == "" {
		return "", "", "", false, fmt.Errorf("TOKEN not found in config file")
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	if url == "" {
		url = defaultURL
	}

	return token, hostname, url, debug, nil
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

	// CPU
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU percent: %w", err)
	}
	if len(cpuPercent) > 0 {
		metrics.CPU.Percent = cpuPercent[0]
	}

	cpuPercentPerCore, err := cpu.Percent(time.Second, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get per-core CPU percent: %w", err)
	}
	metrics.CPU.PerCore = cpuPercentPerCore

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

	return metrics, nil
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
