# OpenList Desktop Service

A cross-platform desktop service with RESTful HTTP API for process management.

## Architecture

This service consists of two components:

1. **HTTP API Service** - The persistent service that provides the REST API
2. **Core Application** - The main OpenList application managed by the service

The HTTP API service runs continuously and provides endpoints to start/stop the core application. When you call `/api/v1/stop`, it stops the core application but leaves the HTTP API service running so you can start it again later.

## Features

- RESTful HTTP API for service control
- Environment variable configuration
- Simple API key authentication
- Cross-platform support (Windows, Linux, macOS)
- Process management and monitoring

## Configuration

The service can be configured using environment variables:

| Variable              | Default     | Description                     |
| --------------------- | ----------- | ------------------------------- |
| `OPENLIST_HOST`       | `127.0.0.1` | API server host address         |
| `OPENLIST_PORT`       | `53211`     | API server port                 |
| `OPENLIST_API_KEY`    | (built-in)  | API authentication key          |
| `OPENLIST_AUTO_START` | `true`      | Auto-start core on service boot |

### Auto-Start Configuration

By default, the service will automatically start the core application when the service starts. You can control this behavior:

- `OPENLIST_AUTO_START=true` or `1`: Enable auto-start (default)
- `OPENLIST_AUTO_START=false` or `0`: Disable auto-start, manual start required

### Setting Environment Variables

**Windows (PowerShell):**

```powershell
$env:OPENLIST_API_KEY="your-secure-api-key"
$env:OPENLIST_PORT="8080"
$env:OPENLIST_AUTO_START="true"
./openlist-desktop-service.exe
```

**Windows (CMD):**

```cmd
set OPENLIST_API_KEY=your-secure-api-key
set OPENLIST_PORT=8080
set OPENLIST_AUTO_START=true
openlist-desktop-service.exe
```

**Linux/macOS:**

```bash
export OPENLIST_API_KEY="your-secure-api-key"
export OPENLIST_PORT="8080"
export OPENLIST_AUTO_START="true"
./openlist-desktop-service
```

## API Endpoints

### Authentication

All protected endpoints require an API key in the `Authorization` header:

```bash
Authorization: your-api-key
# or
Authorization: Bearer your-api-key
```

### Available Endpoints

| Method | Endpoint          | Auth Required | Description             |
| ------ | ----------------- | ------------- | ----------------------- |
| GET    | `/health`         | No            | Health check            |
| GET    | `/api/v1/status`  | Yes           | Get service status      |
| GET    | `/api/v1/version` | Yes           | Get version information |
| POST   | `/api/v1/start`   | Yes           | Start core application  |
| POST   | `/api/v1/stop`    | Yes           | Stop core application   |

### Usage Examples

**Health Check (no auth required):**

```bash
curl http://127.0.0.1:53211/health
```

**Get Status:**

```bash
curl -H "Authorization: your-api-key" http://127.0.0.1:53211/api/v1/status
```

**Start Core Application:**

```bash
curl -X POST -H "Authorization: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"bin_path":"/path/to/binary","log_file":"/path/to/log"}' \
     http://127.0.0.1:53211/api/v1/start
```

**Stop Core Application:**

```bash
curl -X POST -H "Authorization: your-api-key" \
     http://127.0.0.1:53211/api/v1/stop
```

## Building

```bash
cargo build --release
```

## Installation

The service supports automatic installation and management on different platforms:

### Linux

The service automatically detects your Linux init system and installs accordingly:

- **systemd** (most common): Creates service file in `/etc/systemd/system/`
- **OpenRC** (Alpine, Gentoo, etc.): Creates init script in `/etc/init.d/`

**Install Service:**

```bash
sudo ./install-openlist-service
```

**Uninstall Service:**

```bash
sudo ./uninstall-openlist-service
```

#### Init System Detection

The service automatically detects your init system by checking for:

- OpenRC: `/sbin/openrc` or `/usr/bin/rc-update`
- systemd: Default fallback

#### OpenRC Support

For OpenRC-based systems (Alpine Linux, Gentoo, etc.), the service will:

- Create an OpenRC init script at `/etc/init.d/openlist-desktop-service`
- Add the service to the default runlevel using `rc-update`
- Support standard OpenRC commands:
  - `rc-service openlist-desktop-service start`
  - `rc-service openlist-desktop-service stop`
  - `rc-service openlist-desktop-service status`

#### systemd Support

For systemd-based systems, the service will:

- Create a systemd unit file at `/etc/systemd/system/openlist-desktop-service.service`
- Enable the service using `systemctl enable`
- Support standard systemctl commands:
  - `systemctl start openlist-desktop-service`
  - `systemctl stop openlist-desktop-service`
  - `systemctl status openlist-desktop-service`

### Windows

The service installs as a Windows Service that starts automatically with the system.

### macOS

The service installs as a Launch Agent (user service) that runs in user space.

- Service is installed in `~/Library/LaunchAgents/` (user-writable location)
- Service binary is stored in `~/Library/Application Support/`

**Install Service:**

```bash
./install-openlist-service
```

**Uninstall Service:**

```bash
./uninstall-openlist-service
```

See the `install.rs` and `uninstall.rs` for platform-specific service installation details.

### License

This project is inspired by the [clash-verge-service](https://github.com/clash-verge-rev/clash-verge-service) for the original idea and architecture. It is released under the GNU General Public License v3.0 (GPL-3.0).

The [LICENSE](LICENSE) file is included in the repository.
