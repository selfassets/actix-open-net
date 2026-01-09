# VMess 协议

VMess 协议的 Rust 实现，V2Ray 使用的核心加密通信协议。

[![CI](https://github.com/user/actix-open-net/actions/workflows/ci.yml/badge.svg)](https://github.com/user/actix-open-net/actions/workflows/ci.yml)
[![Release](https://github.com/user/actix-open-net/actions/workflows/release.yml/badge.svg)](https://github.com/user/actix-open-net/actions/workflows/release.yml)

## 功能特性

- 完整的 VMess 协议实现
- 多种加密方式：
  - `none` - 无加密
  - `aes-128-cfb` - AES-128-CFB 流加密
  - `aes-128-gcm` - AES-128-GCM AEAD（推荐）
  - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD
- 支持地址类型：IPv4、IPv6、域名
- 基于 Tokio 的异步 TCP 传输
- JSON 配置文件支持
- 启动时自动生成订阅链接
- Docker 支持

## 安装

### 从源码编译

```bash
git clone https://github.com/user/actix-open-net.git
cd actix-open-net
cargo build --release
```

### 从 GitHub Releases 下载

从 [Releases](https://github.com/user/actix-open-net/releases) 下载预编译的二进制文件。

### Docker

```bash
docker pull ghcr.io/user/actix-open-net:latest
```

## 使用方法

### 命令行

```bash
# 显示帮助
vmess --help

# 显示示例配置
vmess --example

# 使用配置文件运行
vmess --config config.json

# 使用环境变量
VMESS_CONFIG=config.json vmess
```

### 配置文件

创建 `config.json` 文件：

```json
{
  "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
  "server_address": "127.0.0.1",
  "server_port": 10086,
  "encryption": "aes-128-gcm",
  "name": "My VMess Server",
  "options": {
    "timeout_seconds": 30,
    "auth_time_window_seconds": 120
  }
}
```

| 字段 | 说明 |
|------|------|
| `user_id` | 用于认证的 UUID |
| `server_address` | 服务器 IP 或域名 |
| `server_port` | 服务器端口 |
| `encryption` | 加密方式：`none`、`aes-128-cfb`、`aes-128-gcm`、`chacha20-poly1305` |
| `name` | 服务器备注名称（可选，用于订阅链接显示） |
| `options.timeout_seconds` | 连接超时时间（默认：30秒） |
| `options.auth_time_window_seconds` | 认证时间窗口（默认：120秒） |

### 订阅链接

启动客户端后会自动输出 VMess 订阅链接，格式为 `vmess://base64(json)`，可直接导入到 V2Ray 客户端：

```
========================================
         VMess Subscription Link        
========================================

vmess://eyJ2IjoiMiIsInBzIjoiTXkgVk1lc3MgU2VydmVyIi...

========================================
```

### Docker 运行

```bash
# 使用默认配置运行
docker run -d -p 10086:10086 ghcr.io/user/actix-open-net:latest

# 使用自定义配置运行
docker run -d -p 10086:10086 \
  -v ./config.json:/app/config/config.json \
  ghcr.io/user/actix-open-net:latest

# 使用 docker-compose
docker-compose up -d
```

## 作为库使用

添加到 `Cargo.toml`：

```toml
[dependencies]
actix-open-net = "0.1"
```

示例代码：

```rust
use actix_open_net::{VmessClient, VmessConfig, Address};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 加载配置
    let config = VmessConfig::new(
        "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
        "127.0.0.1".to_string(),
        10086,
        "aes-128-gcm".to_string(),
    );

    // 创建客户端
    let mut client = VmessClient::new(config)?;

    // 连接服务器
    client.connect().await?;

    // 发送请求
    let target = Address::Domain("example.com".to_string());
    let response = client.request(target, 80, b"GET / HTTP/1.1\r\n\r\n").await?;

    // 关闭连接
    client.close().await?;

    Ok(())
}
```

## 项目结构

```
src/
├── lib.rs          # 库导出
├── main.rs         # 命令行应用
├── crypto/         # 加密模块
│   ├── hash.rs     # MD5、FNV1a、HMAC-MD5
│   ├── aes_cfb.rs  # AES-128-CFB
│   ├── aes_gcm.rs  # AES-128-GCM
│   └── chacha.rs   # ChaCha20-Poly1305
├── user_id.rs      # UUID 管理
├── auth.rs         # HMAC 认证
├── command.rs      # 命令编解码
├── data.rs         # 分块数据处理
├── message.rs      # 请求/响应处理
├── config.rs       # JSON 配置
├── link.rs         # 订阅链接生成
├── error.rs        # 错误类型
├── transport.rs    # TCP 传输
└── client.rs       # 高层客户端
```

## 开发

```bash
# 运行测试
cargo test

# 运行 clippy 检查
cargo clippy

# 格式化代码
cargo fmt

# 构建发布版本
cargo build --release
```

## 许可证

MIT
