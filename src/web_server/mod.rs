//! Shared HTTPS scaffolding used by the `atem serv` servers.
//!
//! Contains TLS cert generation, HTTP request reading, response writing,
//! the access code every page and API requires (`access`), and the
//! `/api/token` endpoint. Each server composes these pieces
//! and adds its own HTML + domain-specific routes.

pub mod access;
pub mod browser;
pub mod cert;
pub mod html;
pub mod net;
pub mod request;
pub mod token_endpoint;
