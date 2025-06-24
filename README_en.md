# OpenList Desktop Service

A cross-platform desktop service for managing multiple processes with a RESTful HTTP API. This service provides comprehensive process management capabilities with built-in monitoring, logging, and configuration persistence.

## Features

- **Cross-Platform Support**: Windows, Linux, and macOS
- **RESTful HTTP API**: Complete process management via HTTP endpoints
- **Process Monitoring**: Real-time status tracking, PID monitoring, and restart counting
- **Auto-Start Support**: Automatically start configured processes on service startup
- **Privilege Escalation**: Run processes with administrator/root privileges when needed
- **Configuration Persistence**: Process configurations are saved and restored automatically
- **Centralized Logging**: Individual log files for each managed process with rotation
- **API Authentication**: Simple but effective API key-based authentication
- **Service Integration**: Native Windows service, systemd, and launchd support

## Architecture

The service consists of several key components:

1. **HTTP API Server** - Provides RESTful endpoints for process management
2. **Core Process Manager** - Handles process lifecycle, monitoring, and configuration
3. **Cross-Platform Service Layer** - Integrates with OS-specific service management
4. **Configuration System** - Persistent storage for process configurations and settings

## Installation

### Quick Install

Download the latest release from the repository and run the installer:

#### Windows

```powershell
# Run as Administrator
.\install-openlist-service.exe
```

#### Linux

```bash
# Run with sudo privileges
sudo ./install-openlist-service
```

#### macOS

```bash
# Run with administrator privileges
sudo ./install-openlist-service
```

### Building from Source

#### Prerequisites

- Rust 1.70+ and Cargo
- Platform-specific dependencies:
  - **Windows**: Visual Studio Build Tools or Visual Studio
  - **Linux**: `build-essential`, `pkg-config`, `libssl-dev`
  - **macOS**: Xcode Command Line Tools

#### Build Commands

```bash
# Clone the repository
git clone https://github.com/OpenListTeam/openlist-desktop-service.git
cd openlist-desktop-service

# Build release version
cargo build --release

# Install the service
sudo ./target/release/install-openlist-service
```

## Configuration

### Environment Variables

The service can be configured using the following environment variables:

| Variable                  | Default     | Description             |
| ------------------------- | ----------- | ----------------------- |
| `PROCESS_MANAGER_HOST`    | `127.0.0.1` | API server bind address |
| `PROCESS_MANAGER_PORT`    | `53211`     | API server port         |
| `PROCESS_MANAGER_API_KEY` | (built-in)  | API authentication key  |

### Setting Environment Variables

#### Windows (PowerShell)

```powershell
$env:PROCESS_MANAGER_API_KEY="your-secure-api-key"
$env:PROCESS_MANAGER_PORT="8080"
```

#### Windows (Command Prompt)

```cmd
set PROCESS_MANAGER_API_KEY=your-secure-api-key
set PROCESS_MANAGER_PORT=8080
```

#### Linux/macOS

```bash
export PROCESS_MANAGER_API_KEY="your-secure-api-key"
export PROCESS_MANAGER_PORT="8080"
```

## Usage

### Starting the Service

The service starts automatically after installation. You can also control it manually:

#### Windows

```powershell
# Start service
Start-Service -Name "openlist_desktop_service"

# Stop service
Stop-Service -Name "openlist_desktop_service"

# Check status
Get-Service -Name "openlist_desktop_service"
```

#### Linux (systemd)

```bash
# Start service
sudo systemctl start openlist-desktop-service

# Stop service
sudo systemctl stop openlist-desktop-service

# Check status
sudo systemctl status openlist-desktop-service
```

#### macOS

```bash
# Start service
sudo launchctl start io.github.openlistteam.openlist.service

# Stop service
sudo launchctl stop io.github.openlistteam.openlist.service
```

### API Usage

Once the service is running, you can interact with it via HTTP API:

```bash
# Health check (no authentication required)
curl http://127.0.0.1:53211/health

# List all processes
curl -H "Authorization: your-api-key" http://127.0.0.1:53211/api/v1/processes

# Get service version
curl -H "Authorization: your-api-key" http://127.0.0.1:53211/api/v1/version
```

## API Reference

### Authentication

All protected endpoints require an API key in the `Authorization` header:

```bash
Authorization: your-api-key
# or
Authorization: Bearer your-api-key
```

### Endpoints

| Method | Endpoint                      | Description                     |
| ------ | ----------------------------- | ------------------------------- |
| GET    | `/health`                     | Health check (no auth required) |
| GET    | `/api/v1/status`              | Get service status              |
| GET    | `/api/v1/version`             | Get version information         |
| GET    | `/api/v1/processes`           | List all processes              |
| POST   | `/api/v1/processes`           | Create new process              |
| GET    | `/api/v1/processes/:id`       | Get process details             |
| PUT    | `/api/v1/processes/:id`       | Update process configuration    |
| DELETE | `/api/v1/processes/:id`       | Delete process                  |
| POST   | `/api/v1/processes/:id/start` | Start process                   |
| POST   | `/api/v1/processes/:id/stop`  | Stop process                    |
| GET    | `/api/v1/processes/:id/logs`  | Get process logs                |

### Example Usage

#### Create a New Process

```bash
curl -X POST -H "Authorization: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "My Application",
       "bin_path": "/path/to/executable",
       "args": ["--port", "8080", "--verbose"],
       "log_file": "/path/to/app.log",
       "working_dir": "/path/to/workdir",
       "auto_restart": false,
       "auto_start": true,
       "run_as_admin": false
     }' \
     http://127.0.0.1:53211/api/v1/processes
```

#### Start a Process

```bash
curl -X POST -H "Authorization: your-api-key" \
     http://127.0.0.1:53211/api/v1/processes/{process-id}/start
```

#### Get Process Logs

```bash
curl -H "Authorization: your-api-key" \
     "http://127.0.0.1:53211/api/v1/processes/{process-id}/logs?lines=50"
```

### Response Format

All API responses follow this standard format:

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": 1640995200
}
```

## Process Configuration

When creating or updating processes, you can specify:

- `name`: Display name for the process
- `bin_path`: Path to the executable binary
- `args`: Array of command-line arguments (optional)
- `log_file`: Path to log file (optional, auto-generated if not provided)
- `working_dir`: Working directory for the process (optional)
- `env_vars`: Environment variables as key-value pairs (optional)
- `auto_restart`: Whether to automatically restart on failure (optional)
- `auto_start`: Whether to start automatically when service starts (optional)
- `run_as_admin`: Whether to run with administrator/root privileges (optional)

## Security Considerations

### API Key Security

- Change the default API key in production environments
- Use environment variables to set the API key securely
- Consider using HTTPS in production with a reverse proxy

### Privilege Escalation

- The `run_as_admin` feature requires the service to run with sufficient privileges
- On Windows, UAC prompts may appear unless the service runs as Administrator
- On Linux/macOS, the service user must have sudo privileges for seamless operation
- Use privilege escalation carefully and only when necessary

## File Locations

### Configuration Files

- **Windows**: `%PROGRAMDATA%\openlist-service-config\process_configs.json`
- **Linux**: `~/.config/openlist-service-config/process_configs.json`
- **macOS**: `~/Library/Application Support/OpenListService/process_configs.json`

### Log Files

- Service logs are stored alongside configuration files
- Individual process logs are stored in locations specified during process creation
- Log rotation is automatically handled (10MB max size, 3 files retained)

## Troubleshooting

### Service Won't Start

1. Check service logs for error messages
2. Verify port 53211 is not in use by another application
3. Ensure proper permissions for configuration directory
4. On Linux/macOS, check systemd/launchd logs

### Process Won't Start

1. Verify the binary path exists and is executable
2. Check if the working directory exists
3. Review process logs for specific error messages
4. Ensure proper permissions for the target binary

### API Authentication Issues

1. Verify the API key is set correctly
2. Check the Authorization header format
3. Ensure the service is running and accessible

## Uninstallation

To remove the service:

### Windows

```powershell
# Run as Administrator
.\uninstall-openlist-service.exe
```

### Linux

```bash
# Run with sudo privileges
sudo ./uninstall-openlist-service
```

### macOS

```bash
# Run with administrator privileges
sudo ./uninstall-openlist-service
```

This will stop all managed processes, remove the service registration, and clean up configuration files.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/OpenListTeam/openlist-desktop-service).
