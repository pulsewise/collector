# Pulsewise Collector

Lightweight system metrics collector that reports CPU, memory, disk, network, and process data to [Pulsewise](https://pulsewise.app).

## Quick Install

```bash
curl -sSL https://pulsewise.app/install-collector.sh | TOKEN=your-token sudo -E bash
```

That's it. The script downloads the binary, writes the config, and starts a systemd service. Hostname is auto-detected.

If you prefer an interactive install (prompts for token and hostname):

```bash
curl -sSL https://pulsewise.app/install-collector.sh | sudo bash
```

## What It Collects

Every 30 seconds, the collector sends:

| Category | Metrics |
|----------|---------|
| **System** | OS, platform, platform version, kernel version, architecture, virtualization type, CPU model |
| **Uptime** | Seconds since boot |
| **Load average** | 1m, 5m, 15m |
| **CPU** | Overall %, per-core %, core count |
| **Memory** | Total, available, used, usage % |
| **Swap** | Total, used, free, usage % |
| **Disks** | Per mount point: device, fstype, total, free, used, usage % |
| **Disk I/O** | Read/write bytes, read/write count, IOPS in progress |
| **Network** | Bytes and packets sent/received per second (rate, not cumulative) |
| **Processes** | Top 10 by CPU: PID, name, command, CPU%, memory%, CPU time, RSS |

See [`payload.json`](payload.json) for a full example of the JSON sent to the API.

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
| `DEBUG` | `false` | Log full response body from the server |

Config file permissions should be `600` (root-only readable).

For local development on macOS, the collector also checks `~/.config/pulsewise-collector/config`.

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
GOOS=linux GOARCH=amd64 go build -o pulsewise-collector-linux-amd64
GOOS=linux GOARCH=arm64 go build -o pulsewise-collector-linux-arm64
```

Or use `./deploy.sh` to compile both architectures and copy them into the Pulsewise Laravel app.

## Managing the Service

```bash
sudo systemctl status pulsewise-collector
sudo journalctl -u pulsewise-collector -f
sudo systemctl restart pulsewise-collector
sudo systemctl stop pulsewise-collector
```

## How It Works

- Collects metrics every 30 seconds using [gopsutil](https://github.com/shirou/gopsutil)
- Sends JSON via `POST` to the configured URL with `Authorization: Bearer <token>`
- Network metrics are computed as per-second rates (delta between intervals); the first collection sends `null` for network
- Runs as a systemd service with automatic restart on failure

## License

MIT
