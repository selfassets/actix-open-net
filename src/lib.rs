//! VMess Protocol Implementation
//!
//! This crate provides a Rust implementation of the VMess protocol,
//! the core encrypted communication protocol used by V2Ray.

pub mod auth;
pub mod client;
pub mod command;
pub mod config;
pub mod crypto;
pub mod data;
pub mod error;
pub mod link;
pub mod message;
pub mod transport;
pub mod user_id;

pub use auth::Authenticator;
pub use client::VmessClient;
pub use command::{Address, Command, CommandCodec, CommandType, EncryptionMethod};
pub use config::VmessConfig;
pub use data::DataProcessor;
pub use error::VmessError;
pub use link::{generate_link, parse_link, LinkError, VmessLinkJson};
pub use message::{Request, RequestBuilder, Response, ResponseParser};
pub use transport::TcpTransport;
pub use user_id::UserId;
