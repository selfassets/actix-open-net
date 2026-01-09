# Design Document: VMess Subscription Link

## Overview

本设计为 VMess 客户端添加订阅链接生成功能。订阅链接遵循 V2Ray 标准格式，使用 `vmess://` 协议前缀加上 Base64 编码的 JSON 配置。

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   VmessConfig   │────▶│  LinkGenerator   │────▶│ vmess://base64  │
│   (with name)   │     │                  │     │   (output)      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### 组件职责

1. **VmessConfig** - 扩展配置结构，添加可选的 `name` 字段
2. **LinkGenerator** - 新模块，负责生成订阅链接
3. **main.rs** - 启动时调用 LinkGenerator 输出链接

## Components and Interfaces

### 1. 扩展 VmessConfig

```rust
/// VMess configuration
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmessConfig {
    pub user_id: String,
    pub server_address: String,
    pub server_port: u16,
    pub encryption: String,
    #[serde(default)]
    pub options: ConfigOptions,
    /// Optional server name/remarks for subscription link
    #[serde(default)]
    pub name: Option<String>,
}
```

### 2. LinkGenerator 模块

```rust
/// V2Ray standard VMess link JSON format (version 2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmessLinkJson {
    /// Version, always "2"
    pub v: String,
    /// Remarks/name
    pub ps: String,
    /// Server address
    pub add: String,
    /// Server port (as string)
    pub port: String,
    /// User UUID
    pub id: String,
    /// Alter ID, always 0
    pub aid: String,
    /// Security/encryption method
    pub scy: String,
    /// Network type, always "tcp"
    pub net: String,
    /// Header type, always "none"
    #[serde(rename = "type")]
    pub header_type: String,
    /// Host (empty for tcp)
    pub host: String,
    /// Path (empty for tcp)
    pub path: String,
    /// TLS setting (empty for no TLS)
    pub tls: String,
}

/// Generate VMess subscription link from config
pub fn generate_link(config: &VmessConfig) -> String;

/// Parse VMess subscription link back to VmessLinkJson
pub fn parse_link(link: &str) -> Result<VmessLinkJson, LinkError>;
```

## Data Models

### VmessLinkJson 字段说明

| 字段 | 类型 | 说明 | 示例值 |
|------|------|------|--------|
| v | String | 版本号 | "2" |
| ps | String | 备注名称 | "My Server" |
| add | String | 服务器地址 | "example.com" |
| port | String | 端口（字符串） | "443" |
| id | String | 用户 UUID | "de305d54-..." |
| aid | String | alterId | "0" |
| scy | String | 加密方式 | "aes-128-gcm" |
| net | String | 传输协议 | "tcp" |
| type | String | 伪装类型 | "none" |
| host | String | 伪装域名 | "" |
| path | String | 路径 | "" |
| tls | String | TLS 设置 | "" |

### 加密方式映射

| VmessConfig.encryption | VmessLinkJson.scy |
|------------------------|-------------------|
| none | none |
| aes-128-cfb | aes-128-cfb |
| aes-128-gcm | aes-128-gcm |
| chacha20-poly1305 | chacha20-poly1305 |

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Link Format Validity

*For any* valid VmessConfig, the generated subscription link SHALL start with "vmess://" and the remainder SHALL be valid standard Base64.

**Validates: Requirements 1.1, 1.3, 2.2**

### Property 2: Round-Trip Encoding

*For any* valid VmessConfig, encoding to a subscription link and then decoding the Base64 SHALL produce valid JSON containing all required fields (v, ps, add, port, id, aid, scy, net, type, host, path, tls).

**Validates: Requirements 1.2, 1.4, 2.1**

### Property 3: Remarks Field Correctness

*For any* VmessConfig:
- If `name` is Some(value), the `ps` field SHALL equal value
- If `name` is None, the `ps` field SHALL equal `{server_address}:{server_port}`

**Validates: Requirements 3.1, 3.2, 3.3**

### Property 4: Field Value Preservation

*For any* VmessConfig, the generated link's decoded JSON SHALL have:
- `add` equal to `config.server_address`
- `port` equal to `config.server_port.to_string()`
- `id` equal to `config.user_id`
- `scy` equal to `config.encryption`

**Validates: Requirements 1.4, 2.1**

## Error Handling

### LinkError

```rust
#[derive(Debug, Error)]
pub enum LinkError {
    #[error("Invalid link format: missing vmess:// prefix")]
    InvalidPrefix,
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    #[error("JSON parse error: {0}")]
    JsonError(String),
}
```

## Testing Strategy

### Unit Tests

- 测试基本链接生成
- 测试带 name 字段的链接生成
- 测试不带 name 字段的默认备注
- 测试各种加密方式的映射
- 测试链接解析

### Property-Based Tests

使用 `proptest` 库进行属性测试：

1. **Property 1**: 生成随机配置，验证链接格式
2. **Property 2**: 生成随机配置，验证 round-trip
3. **Property 3**: 生成带/不带 name 的配置，验证 ps 字段
4. **Property 4**: 生成随机配置，验证字段值保持

配置：每个属性测试运行 100 次迭代。
