//! VMess Protocol Implementation
//!
//! This crate provides a Rust implementation of the VMess protocol,
//! the core encrypted communication protocol used by V2Ray.

pub mod crypto;
pub mod user_id;
pub mod auth;
pub mod command;
pub mod data;
pub mod message;
pub mod config;
pub mod error;
pub mod transport;
pub mod client;

pub use user_id::UserId;
pub use auth::Authenticator;
pub use command::{Command, CommandCodec, Address, EncryptionMethod, CommandType};
pub use data::DataProcessor;
pub use message::{Request, Response, RequestBuilder, ResponseParser};
pub use config::VmessConfig;
pub use error::VmessError;
pub use transport::TcpTransport;
pub use client::VmessClient;
