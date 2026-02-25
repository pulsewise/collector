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
var version = "0.1.0"

const (
	defaultURL          = "https://pulsewise.app/api/collect"
	versionCheckURL     = "https://pulsewise.app/collector/release/latest"
	collectionInterval  = 30 * time.Second
	updateCheckInterval = 6 * time.Hour
	configFilePath      = "/etc/pulsewise-collector/config"
	topProcessesCount   = 10
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
	Timestamp time.Time       `json:"timestamp"`
	Token     string          `json:"token"`
	Hostname  string          `json:"hostname"`
	Uptime    uint64          `json:"uptime"`
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

func main() {
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
// Auto-update
// ─────────────────────────────────────────────────────────────

type latestRelease struct {
	Version string `json:"version"`
}

func runAutoUpdater(config *Config) {
	// Wait before first check so the initial collection can complete.
	time.Sleep(30 * time.Second)
	checkAndUpdate(config)

	ticker := time.NewTicker(updateCheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		checkAndUpdate(config)
	}
}

func checkAndUpdate(config *Config) {
	latest, err := fetchLatestVersion()
	if err != nil {
		if config.Debug {
			log.Printf("[DEBUG] Update check failed: %v", err)
		}
		return
	}

	if latest == version {
		if config.Debug {
			log.Printf("[DEBUG] Already on latest version %s", version)
		}
		return
	}

	log.Printf("Update available: v%s → v%s. Downloading...", version, latest)

	if err := downloadAndReplace(); err != nil {
		log.Printf("Auto-update failed: %v", err)
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

	log.Printf("Successfully sent metrics at %s", time.Now().Format(time.RFC3339))
}

func collectMetrics(config *Config) (*Metrics, error) {
	metrics := &Metrics{
		Timestamp:   time.Now(),
		Token:       config.Token,
		Hostname: config.Hostname,
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
