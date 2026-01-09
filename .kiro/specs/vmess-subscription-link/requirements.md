# Requirements Document

## Introduction

本功能为 VMess 客户端添加订阅链接生成功能。当客户端启动成功后，输出标准的 VMess 订阅链接，方便用户分享配置或导入到其他 V2Ray 客户端。

## Glossary

- **Subscription_Link**: VMess 订阅链接，格式为 `vmess://` 前缀加上 Base64 编码的 JSON 配置
- **Link_Generator**: 订阅链接生成器，负责将配置转换为标准订阅链接格式
- **V2Ray_JSON**: V2Ray 标准的 VMess 链接 JSON 格式

## Requirements

### Requirement 1: 生成 VMess 订阅链接

**User Story:** As a user, I want to generate a VMess subscription link from my configuration, so that I can easily share or import the configuration to other V2Ray clients.

#### Acceptance Criteria

1. WHEN the client starts successfully, THE Link_Generator SHALL output a valid VMess subscription link to stdout
2. THE Link_Generator SHALL encode the configuration as Base64 using the V2Ray standard JSON format
3. THE Subscription_Link SHALL start with the `vmess://` protocol prefix
4. THE Link_Generator SHALL include all essential fields: version, remarks, address, port, user ID, encryption method

### Requirement 2: V2Ray 标准 JSON 格式

**User Story:** As a user, I want the subscription link to follow V2Ray standard format, so that it can be imported by any V2Ray-compatible client.

#### Acceptance Criteria

1. THE Link_Generator SHALL produce JSON with the following fields:
   - `v`: 版本号，固定为 "2"
   - `ps`: 备注名称（可选，默认使用 server_address:port）
   - `add`: 服务器地址
   - `port`: 服务器端口
   - `id`: 用户 UUID
   - `aid`: alterId，固定为 0
   - `scy`: 加密方式
   - `net`: 传输协议，固定为 "tcp"
   - `type`: 伪装类型，固定为 "none"
   - `host`: 伪装域名，空字符串
   - `path`: 路径，空字符串
   - `tls`: TLS 设置，空字符串
2. THE Link_Generator SHALL use standard Base64 encoding (not URL-safe variant)

### Requirement 3: 配置文件支持备注名称

**User Story:** As a user, I want to specify a custom name for my server, so that I can identify it easily in client applications.

#### Acceptance Criteria

1. THE VmessConfig SHALL support an optional `name` field for server remarks
2. WHEN `name` is not provided, THE Link_Generator SHALL use `server_address:port` as the default remarks
3. WHEN `name` is provided, THE Link_Generator SHALL use it as the `ps` field in the subscription link

### Requirement 4: 命令行输出订阅链接

**User Story:** As a user, I want to see the subscription link when the client starts, so that I can copy and share it.

#### Acceptance Criteria

1. WHEN the client loads configuration successfully, THE System SHALL display the subscription link
2. THE System SHALL display the link in a clearly formatted section with a header
3. THE System SHALL also display the decoded JSON for debugging purposes (optional, controlled by verbose flag)
