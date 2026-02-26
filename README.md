# Pulsewise Collector

Lightweight system metrics collector that reports to [Pulsewise](https://pulsewise.app).

## Quick Install

```bash
curl -sSL https://pulsewise.app/collector/install.sh | TOKEN=<your-token> sudo -E bash
```

The script downloads the binary, writes the config, registers the service, and starts it. Hostname is auto-detected from the system. If you omit the `TOKEN=` prefix, the script will prompt for it interactively.

## What It Collects

Every 60 seconds, the collector sends:

| Category | Metrics |
|----------|---------|
| **System** | OS, platform, platform version, kernel, architecture, virtualization type, CPU model |
| **Uptime** | Seconds since boot |
| **Load average** | 1m, 5m, 15m |
| **CPU** | Overall %, per-core %, iowait %, core count |
| **Memory** | Total, available, used, usage % |
| **Swap** | Total, used, free, usage % |
| **Disks** | Per physical mount: device, fstype, total, free, used, usage % (virtual/loop mounts excluded) |
| **Disk I/O** | Cumulative read/write bytes, read/write count, IOPS in progress |
| **Network** | Bytes and packets sent/received per second (per-second rate, not cumulative) |
| **TCP** | Established, TIME_WAIT, CLOSE_WAIT, and LISTEN connection counts |
| **File descriptors** | Open fd count and system maximum |
| **Processes** | Top 10 by CPU: PID, name, command, CPU%, memory%, CPU time, RSS |

Optional integrations (configured separately):

| Category | Metrics |
|----------|---------|
| **PHP-FPM** | Active/idle/total workers, max children reached, slow requests, listen queue, accepted connections |
| **Nginx** | Active connections, reading/writing/waiting, accepts/handled/requests |
| **Port checks** | TCP reachability per port with service name (ssh, mysql, redis, etc.) |

See [`payload.json`](payload.json) for a full example of the JSON sent to the API.

## CLI Commands

```bash
sudo pulsewise-collector version    # show version, check for updates
sudo pulsewise-collector update     # download and install latest version
sudo pulsewise-collector status     # show config, service state, last pulse
sudo pulsewise-collector dump       # print full metrics payload as JSON
sudo pulsewise-collector uninstall  # remove binary, config, and service
```

## Configuration

Config lives at `/etc/pulsewise-collector/config`:

```
TOKEN=your-token-here
```

All other options are optional:

| Key | Default | Description |
|-----|---------|-------------|
| `TOKEN` | *(required)* | Your Pulsewise API token |
| `HOSTNAME` | System hostname | Override the reported hostname |
| `URL` | `https://pulsewise.app/api/collect` | Override the API endpoint |
| `AUTO_UPDATE` | `true` | Set to `false` to disable automatic updates |
| `DEBUG` | `false` | Log full API response body |

### Optional integrations

| Key | Example | Description |
|-----|---------|-------------|
| `FPM_STATUS_URL` | `http://127.0.0.1/fpm-status` | PHP-FPM status page URL (`pm.status_path` must be set in your pool config) |
| `NGINX_STATUS_URL` | `http://127.0.0.1/nginx-status` | Nginx `stub_status` URL |
| `CHECK_PORTS` | `22,80,443,3306,6379` | Comma-separated ports to check TCP availability on |

See [`config.example`](config.example) for a commented reference.

Config file permissions should be `600` (root-only readable).

For local development on macOS, the collector also checks `~/.config/pulsewise-collector/config`.

## Managing the Service

**Linux (systemd)**
```bash
sudo systemctl status pulsewise-collector
sudo journalctl -u pulsewise-collector -f
sudo systemctl restart pulsewise-collector
sudo systemctl stop pulsewise-collector
```

**macOS (launchd)**
```bash
tail -f /var/log/pulsewise-collector.log
sudo launchctl kickstart -k system/app.pulsewise.collector
sudo launchctl bootout system /Library/LaunchDaemons/app.pulsewise.collector.plist
```

## How It Works

- Collects metrics every **60 seconds** using [gopsutil](https://github.com/shirou/gopsutil)
- CPU and process metrics are sampled concurrently over the same 1-second window to keep them aligned
- Virtual/pseudo filesystems (tmpfs, squashfs, loop devices, etc.) are excluded from disk metrics
- Network metrics are per-second rates computed from the delta between collections; the first collection omits network
- Sends JSON via `POST` to the configured URL with `Authorization: Bearer <token>`
- Checks for updates at startup (after 30s) and every 6 hours; updates are applied via service restart
- Runs as a systemd (Linux) or launchd (macOS) service with automatic restart on failure

## Development

```bash
# Create local config
mkdir -p ~/.config/pulsewise-collector
echo "TOKEN=test-token" > ~/.config/pulsewise-collector/config

# Build and run
./build.sh
./pulsewise-collector
```

To point at a local server:

```
TOKEN=test-token
URL=http://localhost:8000/api/collect
DEBUG=true
```

## Cross-Compiling

```bash
GOOS=linux GOARCH=amd64 go build -o pulsewise-collector-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o pulsewise-collector-linux-arm64 .
```

Or run `./deploy.sh` to bump the version, compile all targets, and publish a release.

## License

MIT
