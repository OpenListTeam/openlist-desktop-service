# OpenList 桌面服务

一个跨平台的桌面服务，通过 RESTful HTTP API 管理多个进程。此服务提供全面的进程管理功能，包括内置监控、日志记录和配置持久化。

## 功能特性

- **跨平台支持**：Windows、Linux 和 macOS
- **RESTful HTTP API**：通过 HTTP 端点完整的进程管理
- **进程监控**：实时状态跟踪、PID 监控和重启计数
- **自动启动支持**：服务启动时自动启动配置的进程
- **权限提升**：需要时以管理员/root 权限运行进程
- **配置持久化**：进程配置自动保存和恢复
- **集中日志记录**：每个受管进程的独立日志文件，支持轮转
- **API 认证**：简单而有效的 API 密钥认证
- **服务集成**：原生支持 Windows 服务、systemd 和 launchd

## 系统架构

服务由几个关键组件组成：

1. **HTTP API 服务器** - 提供进程管理的 RESTful 端点
2. **核心进程管理器** - 处理进程生命周期、监控和配置
3. **跨平台服务层** - 与特定操作系统的服务管理集成
4. **配置系统** - 进程配置和设置的持久化存储

## 安装

### 快速安装

从仓库下载最新版本并运行安装程序：

#### Windows

```powershell
# 以管理员身份运行
.\install-openlist-service.exe
```

#### Linux

```bash
# 使用 sudo 权限运行
sudo ./install-openlist-service
```

#### macOS

```bash
# 使用管理员权限运行
sudo ./install-openlist-service
```

### 从源码构建

#### 先决条件

- Rust 1.70+ 和 Cargo
- 平台特定依赖：
  - **Windows**：Visual Studio Build Tools 或 Visual Studio
  - **Linux**：`build-essential`、`pkg-config`、`libssl-dev`
  - **macOS**：Xcode 命令行工具

#### 构建命令

```bash
# 克隆仓库
git clone https://github.com/OpenListTeam/openlist-desktop-service.git
cd openlist-desktop-service

# 构建发布版本
cargo build --release

# 安装服务
sudo ./target/release/install-openlist-service
```

## 配置

### 环境变量

可以使用以下环境变量配置服务：

| 变量                      | 默认值      | 描述               |
| ------------------------- | ----------- | ------------------ |
| `PROCESS_MANAGER_HOST`    | `127.0.0.1` | API 服务器绑定地址 |
| `PROCESS_MANAGER_PORT`    | `53211`     | API 服务器端口     |
| `PROCESS_MANAGER_API_KEY` | (内置)      | API 认证密钥       |

### 设置环境变量

#### Windows (PowerShell)

```powershell
$env:PROCESS_MANAGER_API_KEY="your-secure-api-key"
$env:PROCESS_MANAGER_PORT="8080"
```

#### Windows (命令提示符)

```cmd
set PROCESS_MANAGER_API_KEY=your-secure-api-key
set PROCESS_MANAGER_PORT=8080
```

#### Linux/macOS

```bash
export PROCESS_MANAGER_API_KEY="your-secure-api-key"
export PROCESS_MANAGER_PORT="8080"
```

## 使用方法

### 启动服务

服务在安装后会自动启动。您也可以手动控制：

#### Windows

```powershell
# 启动服务
Start-Service -Name "openlist_desktop_service"

# 停止服务
Stop-Service -Name "openlist_desktop_service"

# 检查状态
Get-Service -Name "openlist_desktop_service"
```

#### Linux (systemd)

```bash
# 启动服务
sudo systemctl start openlist-desktop-service

# 停止服务
sudo systemctl stop openlist-desktop-service

# 检查状态
sudo systemctl status openlist-desktop-service
```

#### macOS

```bash
# 启动服务
sudo launchctl start io.github.openlistteam.openlist.service

# 停止服务
sudo launchctl stop io.github.openlistteam.openlist.service
```

### API 使用

服务运行后，您可以通过 HTTP API 与其交互：

```bash
# 检查（无需认证）
curl http://127.0.0.1:53211/health

# 列出所有进程
curl -H "Authorization: your-api-key" http://127.0.0.1:53211/api/v1/processes

# 获取服务版本
curl -H "Authorization: your-api-key" http://127.0.0.1:53211/api/v1/version
```

## API 参考

### 认证

所有受保护的端点都需要在 `Authorization` 头中提供 API 密钥：

```bash
Authorization: your-api-key
# 或
Authorization: Bearer your-api-key
```

### 端点

| 方法   | 端点                          | 描述                 |
| ------ | ----------------------------- | -------------------- |
| GET    | `/health`                     | 检查（无需认证）     |
| GET    | `/api/v1/status`              | 获取服务状态         |
| GET    | `/api/v1/version`             | 获取版本信息         |
| POST   | `/api/v1/service/stop`        | 停止整个服务         |
| GET    | `/api/v1/processes`           | 列出所有进程         |
| POST   | `/api/v1/processes`           | 创建新进程           |
| GET    | `/api/v1/processes/:id`       | 获取进程详情         |
| PUT    | `/api/v1/processes/:id`       | 更新进程配置         |
| DELETE | `/api/v1/processes/:id`       | 删除进程             |
| POST   | `/api/v1/processes/:id/start` | 启动进程             |
| POST   | `/api/v1/processes/:id/stop`  | 停止进程             |
| GET    | `/api/v1/processes/:id/logs`  | 获取进程日志         |

### 使用示例

#### 创建新进程

```bash
curl -X POST -H "Authorization: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "我的应用程序",
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

#### 启动进程

```bash
curl -X POST -H "Authorization: your-api-key" \
     http://127.0.0.1:53211/api/v1/processes/{process-id}/start
```

#### 获取进程日志

```bash
curl -H "Authorization: your-api-key" \
     "http://127.0.0.1:53211/api/v1/processes/{process-id}/logs?lines=50"
```

#### 停止服务

```bash
curl -X POST -H "Authorization: your-api-key" \
     http://127.0.0.1:53211/api/v1/service/stop
```

### 响应格式

所有 API 响应都遵循这个标准格式：

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": 1640995200
}
```

## 进程配置

创建或更新进程时，您可以指定：

- `name`：进程的显示名称
- `bin_path`：可执行二进制文件的路径
- `args`：命令行参数数组（可选）
- `log_file`：日志文件路径（可选，如果未提供会自动生成）
- `working_dir`：进程的工作目录（可选）
- `env_vars`：环境变量键值对（可选）
- `auto_restart`：是否在失败时自动重启（可选）
- `auto_start`：服务启动时是否自动启动（可选）
- `run_as_admin`：是否以管理员/root 权限运行（可选）

## 安全考虑

### API 密钥安全

- 在生产环境中更改默认 API 密钥
- 使用环境变量安全地设置 API 密钥
- 在生产环境中考虑使用反向代理配置 HTTPS

### 权限提升

- `run_as_admin` 功能需要服务以足够的权限运行
- 在 Windows 上，除非服务以管理员身份运行，否则可能出现 UAC 提示
- 在 Linux/macOS 上，服务用户必须具有 sudo 权限才能无缝操作
- 谨慎使用权限提升，仅在必要时使用

## 文件位置

### 日志文件

- 服务日志存储在配置文件旁边
- 单个进程日志存储在进程创建时指定的位置
- 日志轮转自动处理（最大 10MB，保留 3 个文件）

## 故障排除

### 服务无法启动

1. 检查服务日志中的错误消息
2. 验证端口 53211 未被其他应用程序占用
3. 确保配置目录具有适当的权限
4. 在 Linux/macOS 上，检查 systemd/launchd 日志

### 进程无法启动

1. 验证二进制文件路径存在且可执行
2. 检查工作目录是否存在
3. 查看进程日志了解具体错误消息
4. 确保目标二进制文件具有适当的权限

### API 认证问题

1. 验证 API 密钥设置正确
2. 检查 Authorization 头格式
3. 确保服务正在运行且可访问

## 卸载

要移除服务：

### Windows

```powershell
# 以管理员身份运行
.\uninstall-openlist-service.exe
```

### Linux

```bash
# 使用 sudo 权限运行
sudo ./uninstall-openlist-service
```

### macOS

```bash
# 使用管理员权限运行
sudo ./uninstall-openlist-service
```

这将停止所有受管进程，移除服务注册，并清理配置文件。

## 贡献

1. Fork 仓库
2. 创建功能分支
3. 进行更改
4. 如适用，添加测试
5. 提交拉取请求

## 许可证

此项目采用 GPL-3.0 许可证 - 详情请参见 [LICENSE](LICENSE) 文件。

## 支持

如有问题、疑问或贡献，请访问 [GitHub 仓库](https://github.com/OpenListTeam/openlist-desktop-service)。
