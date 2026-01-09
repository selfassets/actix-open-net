# Requirements Document

## Introduction

本文档定义了在 Rust 中实现 VMess 协议的需求。VMess 是 V2Ray 项目的核心加密通信协议，用于客户端和服务器之间的安全数据传输。该协议是无状态的，支持多种加密方式，并通过基于时间的认证机制验证客户端身份。

## Glossary

- **VMess_Protocol**: V2Ray 项目原创的加密通信协议，用于客户端和服务器之间的安全数据传输
- **User_ID**: 一个 16 字节的 UUID，作为用户身份标识和认证令牌
- **Authentication_Info**: 16 字节的 HMAC 哈希值，用于验证客户端请求的合法性
- **Command_Section**: 包含加密参数、目标地址和端口等信息的指令部分
- **Data_Section**: 实际传输数据的部分，可分块传输
- **AES_128_CFB**: 用于加密指令部分的对称加密算法
- **ChaCha20_Poly1305**: 一种 AEAD 加密算法，用于数据部分加密
- **AES_128_GCM**: 一种 AEAD 加密算法，用于数据部分加密
- **Request_Header**: 客户端请求的头部，包含认证信息和指令部分
- **Response_Header**: 服务器响应的头部，包含响应认证和选项信息
- **Chunk**: 数据分块，标准格式下数据被分成多个小块传输

## Requirements

### Requirement 1: User ID 管理

**User Story:** As a developer, I want to manage User IDs (UUIDs), so that I can identify and authenticate users in the VMess protocol.

#### Acceptance Criteria

1. THE User_ID_Manager SHALL generate valid 16-byte UUIDs conforming to UUID v4 format
2. THE User_ID_Manager SHALL parse UUID strings in the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
3. THE User_ID_Manager SHALL serialize UUIDs back to string format
4. IF an invalid UUID string is provided, THEN THE User_ID_Manager SHALL return a descriptive error

### Requirement 2: 认证信息生成与验证

**User Story:** As a developer, I want to generate and verify authentication information, so that the server can validate client requests.

#### Acceptance Criteria

1. WHEN generating authentication info, THE Authentication_Generator SHALL compute a 16-byte HMAC using User_ID and UTC timestamp
2. THE Authentication_Generator SHALL use MD5 hash of (User_ID + timestamp bytes) as the authentication value
3. WHEN verifying authentication, THE Authentication_Verifier SHALL accept timestamps within a configurable time window (default ±120 seconds)
4. IF the timestamp is outside the allowed window, THEN THE Authentication_Verifier SHALL reject the request
5. IF the HMAC does not match, THEN THE Authentication_Verifier SHALL reject the request

### Requirement 3: 指令部分编码与解码

**User Story:** As a developer, I want to encode and decode the command section, so that I can transmit encryption parameters and target address information.

#### Acceptance Criteria

1. THE Command_Encoder SHALL encode the following fields: version, data encryption IV (16 bytes), data encryption key (16 bytes), response authentication (1 byte), options (1 byte), encryption method (4 bits), command type (1 byte), port (2 bytes), address type (1 byte), address (variable), random padding, and checksum (4 bytes)
2. THE Command_Encoder SHALL encrypt the command section using AES-128-CFB with IV derived from MD5(timestamp) and key from User_ID
3. THE Command_Decoder SHALL decrypt and parse the command section
4. THE Command_Encoder SHALL support address types: IPv4 (0x01), domain name (0x02), IPv6 (0x03)
5. THE Command_Encoder SHALL compute checksum using FNV1a hash of the command data
6. IF decryption or parsing fails, THEN THE Command_Decoder SHALL return a descriptive error
7. THE Pretty_Printer SHALL format Command objects into human-readable string representation
8. FOR ALL valid Command objects, encoding then decoding SHALL produce an equivalent object (round-trip property)

### Requirement 4: 数据部分处理

**User Story:** As a developer, I want to process the data section with chunked transfer, so that I can securely transmit actual payload data.

#### Acceptance Criteria

1. WHEN Opt(S) is enabled, THE Data_Processor SHALL use standard chunked format
2. THE Data_Processor SHALL encode each chunk with 2-byte length prefix followed by data packet
3. THE Data_Processor SHALL support encryption methods: none (0x00), AES-128-CFB (0x01), AES-128-GCM (0x03), ChaCha20-Poly1305 (0x04)
4. WHEN using AEAD encryption, THE Data_Processor SHALL include authentication tag in each chunk
5. THE Data_Processor SHALL signal end of transmission with an empty data packet (L=0 for no encryption, or auth tag length for encrypted)
6. THE Data_Processor SHALL decrypt and reassemble chunks into original data
7. IF chunk authentication fails, THEN THE Data_Processor SHALL return an error and abort transmission
8. FOR ALL valid data payloads, chunking then reassembling SHALL produce the original data (round-trip property)

### Requirement 5: 请求构建与解析

**User Story:** As a developer, I want to build and parse VMess client requests, so that I can initiate connections to VMess servers.

#### Acceptance Criteria

1. THE Request_Builder SHALL construct requests with: 16-byte authentication info, encrypted command section, and data section
2. THE Request_Builder SHALL generate random IV and key for data encryption
3. THE Request_Parser SHALL extract and validate authentication info
4. THE Request_Parser SHALL decrypt and parse the command section
5. THE Request_Parser SHALL process the data section according to the specified encryption method
6. IF any parsing step fails, THEN THE Request_Parser SHALL return a descriptive error indicating the failure point
7. FOR ALL valid Request objects, serializing then parsing SHALL produce an equivalent object (round-trip property)

### Requirement 6: 响应构建与解析

**User Story:** As a developer, I want to build and parse VMess server responses, so that I can receive data from VMess servers.

#### Acceptance Criteria

1. THE Response_Builder SHALL construct responses with: response authentication (1 byte), options (1 byte), command (1 byte), command length (1 byte), optional command content, and actual response data
2. THE Response_Builder SHALL encrypt the response header using AES-128-CFB with IV=MD5(request data IV) and Key=MD5(request data key)
3. THE Response_Parser SHALL decrypt and parse the response header
4. THE Response_Parser SHALL process the response data according to the encryption settings
5. IF response authentication does not match the expected value, THEN THE Response_Parser SHALL reject the response
6. FOR ALL valid Response objects, serializing then parsing SHALL produce an equivalent object (round-trip property)

### Requirement 7: 加密算法支持

**User Story:** As a developer, I want to support multiple encryption algorithms, so that I can provide flexible security options.

#### Acceptance Criteria

1. THE Crypto_Module SHALL implement AES-128-CFB encryption and decryption
2. THE Crypto_Module SHALL implement AES-128-GCM encryption and decryption with authentication
3. THE Crypto_Module SHALL implement ChaCha20-Poly1305 encryption and decryption with authentication
4. THE Crypto_Module SHALL implement MD5 hashing for key derivation
5. THE Crypto_Module SHALL implement FNV1a hashing for checksum calculation
6. THE Crypto_Module SHALL implement HMAC-MD5 for authentication info generation
7. FOR ALL encryption algorithms, encrypting then decrypting with the same key SHALL produce the original data (round-trip property)

### Requirement 8: 网络传输层

**User Story:** As a developer, I want to handle TCP connections, so that I can transmit VMess protocol data over the network.

#### Acceptance Criteria

1. THE Transport_Layer SHALL establish TCP connections to specified addresses
2. THE Transport_Layer SHALL support both IPv4 and IPv6 addresses
3. THE Transport_Layer SHALL support domain name resolution
4. THE Transport_Layer SHALL handle connection timeouts with configurable duration
5. THE Transport_Layer SHALL provide async read and write operations
6. IF connection fails, THEN THE Transport_Layer SHALL return a descriptive error with the failure reason

### Requirement 9: 配置管理

**User Story:** As a developer, I want to configure VMess client and server settings, so that I can customize the protocol behavior.

#### Acceptance Criteria

1. THE Config_Manager SHALL parse configuration from JSON format
2. THE Config_Manager SHALL support specifying: User_ID, server address, server port, encryption method, and security options
3. THE Config_Manager SHALL validate configuration values
4. IF configuration is invalid, THEN THE Config_Manager SHALL return a descriptive error
5. THE Config_Manager SHALL serialize configuration back to JSON format
6. FOR ALL valid Config objects, serializing to JSON then parsing SHALL produce an equivalent object (round-trip property)

### Requirement 10: 错误处理

**User Story:** As a developer, I want comprehensive error handling, so that I can diagnose and handle protocol failures.

#### Acceptance Criteria

1. THE Error_Handler SHALL define distinct error types for: authentication failure, encryption failure, parsing failure, network failure, and configuration error
2. THE Error_Handler SHALL include contextual information in error messages
3. THE Error_Handler SHALL support error chaining for nested failures
4. WHEN an error occurs, THE Error_Handler SHALL not expose sensitive information (keys, IVs) in error messages
