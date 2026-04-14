//! Shared HTTPS scaffolding used by `atem serv rtc` and `atem serv convo`.
//!
//! Contains TLS cert generation, HTTP request reading, response writing,
//! and the `/api/token` endpoint. Each server composes these pieces
//! and adds its own HTML + domain-specific routes.

pub mod cert;
pub mod request;
pub mod token_endpoint;
