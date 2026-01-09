//! VMess Protocol Client
//!
//! A Rust implementation of the VMess protocol.

use actix_open_net::{
    Address, CommandCodec, EncryptionMethod, RequestBuilder, UserId, VmessClient, VmessConfig,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

fn print_usage() {
    println!("VMess Protocol Client");
    println!();
    println!("Usage:");
    println!("  vmess --config <path>     Run with config file");
    println!("  vmess --help              Show this help");
    println!("  vmess --version           Show version");
    println!("  vmess --example           Show example config");
    println!();
    println!("Environment Variables:");
    println!("  VMESS_CONFIG              Path to config file");
    println!();
    println!("Config File Format (JSON):");
    println!("  {{");
    println!("    \"user_id\": \"uuid-string\",");
    println!("    \"server_address\": \"127.0.0.1\",");
    println!("    \"server_port\": 10086,");
    println!("    \"encryption\": \"aes-128-gcm\",");
    println!("    \"options\": {{");
    println!("      \"timeout_seconds\": 30,");
    println!("      \"auth_time_window_seconds\": 120");
    println!("    }}");
    println!("  }}");
}

fn print_version() {
    println!("vmess {}", env!("CARGO_PKG_VERSION"));
}

fn print_example_config() {
    let example = r#"{
  "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
  "server_address": "127.0.0.1",
  "server_port": 10086,
  "encryption": "aes-128-gcm",
  "options": {
    "timeout_seconds": 30,
    "auth_time_window_seconds": 120
  }
}"#;
    println!("{}", example);
}

fn load_config(path: &PathBuf) -> Result<VmessConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    let config: VmessConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    config.validate().map_err(|e| format!("Invalid config: {}", e))?;

    Ok(config)
}

fn find_config_path(args: &[String]) -> Option<PathBuf> {
    // Check command line args
    for i in 0..args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if let Some(path) = args.get(i + 1) {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Check environment variable
    if let Ok(path) = env::var("VMESS_CONFIG") {
        return Some(PathBuf::from(path));
    }

    // Check default locations
    let default_paths = [
        "config.json",
        "./config/config.json",
        "/etc/vmess/config.json",
    ];

    for path in default_paths {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    None
}

fn demo_mode() {
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

    // Example 4: Supported encryption methods
    println!("4. Supported encryption methods:");
    println!("   - none              : No encryption");
    println!("   - aes-128-cfb       : AES-128-CFB stream cipher");
    println!("   - aes-128-gcm       : AES-128-GCM AEAD (recommended)");
    println!("   - chacha20-poly1305 : ChaCha20-Poly1305 AEAD\n");

    println!("Run with --help for usage information.");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Handle flags
    for arg in &args {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return;
            }
            "--version" | "-V" => {
                print_version();
                return;
            }
            "--example" => {
                print_example_config();
                return;
            }
            _ => {}
        }
    }

    // Try to find config file
    let config_path = find_config_path(&args);

    match config_path {
        Some(path) => {
            println!("Loading config from: {}", path.display());

            match load_config(&path) {
                Ok(config) => {
                    println!("Config loaded successfully!");
                    println!("  Server: {}:{}", config.server_address, config.server_port);
                    println!("  Encryption: {}", config.encryption);
                    println!("  Timeout: {}s", config.options.timeout_seconds);
                    println!();

                    // Create client
                    match VmessClient::new(config) {
                        Ok(mut client) => {
                            println!("VMess client initialized.");
                            println!("Connecting to server...");

                            match client.connect().await {
                                Ok(()) => {
                                    println!("Connected successfully!");
                                    // Client is ready for use
                                    // In a real application, you would handle requests here
                                }
                                Err(e) => {
                                    eprintln!("Connection failed: {}", e);
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to create client: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => {
            // No config file, run demo mode
            demo_mode();
        }
    }
}
