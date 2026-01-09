# Implementation Plan: VMess Protocol

## Overview

本实现计划将 VMess 协议设计分解为可执行的编码任务。采用自底向上的方式，先实现基础加密模块，然后逐步构建协议层组件，最后集成为完整的客户端/服务器实现。

## Tasks

- [x] 1. 项目设置和依赖配置
  - 更新 Cargo.toml 添加必要依赖
  - 创建模块结构
  - 设置测试框架
  - _Requirements: 项目基础设施_

- [x] 2. 实现加密模块
  - [x] 2.1 实现 MD5、FNV1a、HMAC-MD5 哈希函数
    - 在 `src/crypto/hash.rs` 中实现
    - MD5 返回 16 字节，FNV1a 返回 4 字节
    - _Requirements: 7.4, 7.5, 7.6_
  - [ ]* 2.2 编写哈希函数属性测试
    - **Property 17: Hash Function Consistency**
    - **Validates: Requirements 7.4, 7.5, 7.6**
  - [x] 2.3 实现 AES-128-CFB 加密/解密
    - 在 `src/crypto/aes_cfb.rs` 中实现
    - _Requirements: 7.1_
  - [x] 2.4 实现 AES-128-GCM 加密/解密
    - 在 `src/crypto/aes_gcm.rs` 中实现
    - 包含认证标签处理
    - _Requirements: 7.2_
  - [x] 2.5 实现 ChaCha20-Poly1305 加密/解密
    - 在 `src/crypto/chacha.rs` 中实现
    - 包含认证标签处理
    - _Requirements: 7.3_
  - [ ]* 2.6 编写加密算法属性测试
    - **Property 16: Crypto Round-Trip (All Algorithms)**
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.7**

- [x] 3. Checkpoint - 确保加密模块测试通过
  - 确保所有测试通过，如有问题请询问用户

- [x] 4. 实现 User ID 模块
  - [x] 4.1 实现 UserId 结构体和基本操作
    - 在 `src/user_id.rs` 中实现
    - 生成、解析、序列化功能
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
  - [ ]* 4.2 编写 User ID 属性测试
    - **Property 1: UUID Round-Trip**
    - **Property 2: UUID Generation Validity**
    - **Property 3: Invalid UUID Rejection**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4**

- [x] 5. 实现认证模块
  - [x] 5.1 实现 Authenticator 结构体
    - 在 `src/auth.rs` 中实现
    - 生成和验证认证信息
    - 支持可配置时间窗口
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  - [ ]* 5.2 编写认证模块属性测试
    - **Property 4: Authentication Generation Consistency**
    - **Property 5: Authentication Time Window Acceptance**
    - **Property 6: Authentication Time Window Rejection**
    - **Property 7: Authentication HMAC Rejection**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

- [x] 6. Checkpoint - 确保基础模块测试通过
  - 确保所有测试通过，如有问题请询问用户

- [x] 7. 实现 Command 模块
  - [x] 7.1 定义 Command 相关数据结构
    - 在 `src/command.rs` 中定义
    - Command, CommandOptions, EncryptionMethod, CommandType, Address
    - _Requirements: 3.1, 3.4_
  - [x] 7.2 实现 CommandCodec 编码功能
    - 编码所有字段，计算 FNV1a 校验和
    - AES-128-CFB 加密
    - _Requirements: 3.1, 3.2, 3.5_
  - [x] 7.3 实现 CommandCodec 解码功能
    - 解密和解析命令部分
    - 验证校验和
    - _Requirements: 3.3, 3.6_
  - [x] 7.4 实现 Command pretty_print 功能
    - 格式化为人类可读字符串
    - _Requirements: 3.7_
  - [ ]* 7.5 编写 Command 属性测试
    - **Property 8: Command Round-Trip**
    - **Property 9: Command Error Handling**
    - **Validates: Requirements 3.1-3.8**

- [x] 8. 实现 Data Processor 模块
  - [x] 8.1 定义 Chunk 数据结构
    - 在 `src/data.rs` 中定义
    - _Requirements: 4.2_
  - [x] 8.2 实现 DataProcessor 编码功能
    - 分块编码，支持所有加密方法
    - AEAD 认证标签处理
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [x] 8.3 实现 DataProcessor 解码功能
    - 解密和重组数据块
    - 验证认证标签
    - _Requirements: 4.6, 4.7_
  - [x] 8.4 实现 EOT 块处理
    - 创建和检测传输结束块
    - _Requirements: 4.5_
  - [ ]* 8.5 编写 Data Processor 属性测试
    - **Property 10: Data Chunk Round-Trip**
    - **Property 11: Data Chunk Authentication Failure**
    - **Validates: Requirements 4.1-4.8**

- [x] 9. Checkpoint - 确保协议组件测试通过
  - 确保所有测试通过，如有问题请询问用户

- [x] 10. 实现 Request/Response 模块
  - [x] 10.1 定义 Request 和 Response 数据结构
    - 在 `src/message.rs` 中定义
    - _Requirements: 5.1, 6.1_
  - [x] 10.2 实现 RequestBuilder
    - 构建完整 VMess 请求
    - 生成随机 IV 和 Key
    - _Requirements: 5.1, 5.2_
  - [x] 10.3 实现 RequestParser
    - 解析和验证请求
    - _Requirements: 5.3, 5.4, 5.5, 5.6_
  - [ ]* 10.4 编写 Request 属性测试
    - **Property 12: Request Round-Trip**
    - **Property 13: Request Error Handling**
    - **Validates: Requirements 5.1-5.7**
  - [x] 10.5 实现 ResponseBuilder
    - 构建 VMess 响应
    - _Requirements: 6.1, 6.2_
  - [x] 10.6 实现 ResponseParser
    - 解析和验证响应
    - _Requirements: 6.3, 6.4, 6.5_
  - [ ]* 10.7 编写 Response 属性测试
    - **Property 14: Response Round-Trip**
    - **Property 15: Response Authentication Rejection**
    - **Validates: Requirements 6.1-6.6**

- [x] 11. 实现配置模块
  - [x] 11.1 定义 VmessConfig 数据结构
    - 在 `src/config.rs` 中定义
    - 使用 serde 进行 JSON 序列化
    - _Requirements: 9.1, 9.2_
  - [x] 11.2 实现配置验证
    - 验证所有配置值
    - _Requirements: 9.3, 9.4_
  - [ ]* 11.3 编写配置模块属性测试
    - **Property 18: Config Round-Trip**
    - **Property 19: Config Validation Error**
    - **Validates: Requirements 9.1-9.6**

- [x] 12. 实现错误处理模块
  - [x] 12.1 定义错误类型层次结构
    - 在 `src/error.rs` 中定义
    - 使用 thiserror 宏
    - _Requirements: 10.1, 10.2, 10.3_
  - [ ]* 12.2 编写错误安全性属性测试
    - **Property 20: Error Message Security**
    - **Validates: Requirements 10.4**

- [x] 13. Checkpoint - 确保所有核心模块测试通过
  - 确保所有测试通过，如有问题请询问用户

- [x] 14. 实现传输层模块
  - [x] 14.1 实现 TcpTransport
    - 在 `src/transport.rs` 中实现
    - 异步连接、发送、接收
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

- [x] 15. 集成和主入口
  - [x] 15.1 创建 VMess Client 结构体
    - 在 `src/client.rs` 中实现
    - 整合所有模块
    - _Requirements: 所有_
  - [x] 15.2 更新 main.rs 示例
    - 提供基本使用示例
    - _Requirements: 所有_

- [x] 16. Final Checkpoint - 确保所有测试通过
  - 确保所有测试通过，如有问题请询问用户

## Notes

- 标记 `*` 的任务为可选任务，可跳过以加快 MVP 开发
- 每个任务引用具体需求以保证可追溯性
- Checkpoint 任务确保增量验证
- 属性测试验证通用正确性属性
- 单元测试验证具体示例和边界条件
