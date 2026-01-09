# Implementation Plan: VMess Subscription Link

## Overview

实现 VMess 订阅链接生成功能，包括扩展配置结构、创建链接生成模块、更新 CLI 输出。

## Tasks

- [x] 1. 扩展 VmessConfig 结构
  - [x] 1.1 在 VmessConfig 中添加可选的 `name` 字段
    - 修改 `src/config.rs`
    - 添加 `#[serde(default)] pub name: Option<String>`
    - 更新 `VmessConfig::new()` 方法
    - _Requirements: 3.1_

  - [x] 1.2 编写 name 字段的单元测试
    - 测试带 name 的 JSON 解析
    - 测试不带 name 的 JSON 解析（默认 None）
    - _Requirements: 3.1_

- [x] 2. 创建 LinkGenerator 模块
  - [x] 2.1 创建 `src/link.rs` 模块
    - 定义 `VmessLinkJson` 结构体
    - 定义 `LinkError` 错误类型
    - 实现 `generate_link()` 函数
    - 实现 `parse_link()` 函数
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2_

  - [x] 2.2 在 `src/lib.rs` 中导出 link 模块
    - 添加 `pub mod link;`
    - 导出公共类型
    - _Requirements: 1.1_

  - [x] 2.3 编写属性测试：链接格式有效性
    - **Property 1: Link Format Validity**
    - **Validates: Requirements 1.1, 1.3, 2.2**

  - [x] 2.4 编写属性测试：Round-Trip 编码
    - **Property 2: Round-Trip Encoding**
    - **Validates: Requirements 1.2, 1.4, 2.1**

  - [x] 2.5 编写属性测试：备注字段正确性
    - **Property 3: Remarks Field Correctness**
    - **Validates: Requirements 3.1, 3.2, 3.3**

  - [x] 2.6 编写属性测试：字段值保持
    - **Property 4: Field Value Preservation**
    - **Validates: Requirements 1.4, 2.1**

- [x] 3. 更新 CLI 输出订阅链接
  - [x] 3.1 修改 `src/main.rs` 在启动成功后输出订阅链接
    - 在配置加载成功后调用 `generate_link()`
    - 格式化输出链接
    - _Requirements: 4.1, 4.2_

- [x] 4. 更新配置文件示例和文档
  - [x] 4.1 更新 `config.example.json` 添加 name 字段示例
    - _Requirements: 3.1_

  - [x] 4.2 更新 `README.md` 文档
    - 添加订阅链接功能说明
    - 更新配置文件字段说明
    - _Requirements: 4.1, 4.2_

- [x] 5. Checkpoint - 确保所有测试通过
  - 运行 `cargo test`
  - 运行 `cargo clippy`
  - 确保所有测试通过，如有问题请询问用户

## Notes

- 使用 `base64` crate 进行 Base64 编码
- 使用 `proptest` crate 进行属性测试
- 订阅链接格式遵循 V2Ray v2 标准
