//! VMess Protocol Example
//!
//! This example demonstrates basic usage of the VMess protocol implementation.

use actix_open_net::{
    VmessConfig, Address, EncryptionMethod,
    RequestBuilder, UserId, CommandCodec,
};
use std::str::FromStr;

fn main() {
    println!("VMess Protocol Implementation");
    println!("==============================\n");

    // Example 1: Create configuration from JSON
    let config_json = r#"{
        "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
        "server_address": "127.0.0.1",
        "server_port": 10086,
        "encryption": "aes-128-gcm"
    }"#;

    println!("1. Configuration from JSON:");
    println!("{}\n", config_json);

    let config: VmessConfig = serde_json::from_str(config_json).expect("Invalid JSON");
    config.validate().expect("Invalid configuration");
    println!("   Configuration validated successfully!\n");

    // Example 2: Create configuration programmatically
    println!("2. Programmatic configuration:");
    let config = VmessConfig::new(
        "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
        "example.com".to_string(),
        443,
        "chacha20-poly1305".to_string(),
    );
    println!("   Server: {}:{}", config.server_address, config.server_port);
    println!("   Encryption: {}\n", config.encryption);

    // Example 3: Build a VMess request
    println!("3. Building VMess request:");
    let user_id = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap();
    let builder = RequestBuilder::new(user_id);
    
    let target = Address::Domain("target.example.com".to_string());
    let payload = b"GET / HTTP/1.1\r\nHost: target.example.com\r\n\r\n";
    
    let (request_bytes, command) = builder
        .build(target, 80, payload, EncryptionMethod::Aes128Gcm)
        .expect("Failed to build request");
    
    println!("   Target: {}", CommandCodec::pretty_print(&command));
    println!("   Request size: {} bytes\n", request_bytes.len());

    // Example 4: Create VMess client (async usage)
    println!("4. VMess Client usage (async):");
    println!("   ```rust");
    println!("   let config = VmessConfig::new(...);");
    println!("   let mut client = VmessClient::new(config)?;");
    println!("   ");
    println!("   // Connect to VMess server");
    println!("   client.connect().await?;");
    println!("   ");
    println!("   // Send request through proxy");
    println!("   let target = Address::Domain(\"example.com\".to_string());");
    println!("   let response = client.request(target, 80, b\"GET /\").await?;");
    println!("   ");
    println!("   // Close connection");
    println!("   client.close().await?;");
    println!("   ```\n");

    // Example 5: Supported encryption methods
    println!("5. Supported encryption methods:");
    println!("   - none           : No encryption");
    println!("   - aes-128-cfb    : AES-128-CFB stream cipher");
    println!("   - aes-128-gcm    : AES-128-GCM AEAD (recommended)");
    println!("   - chacha20-poly1305 : ChaCha20-Poly1305 AEAD\n");

    println!("For full documentation, see: https://github.com/example/vmess-rs");
}
