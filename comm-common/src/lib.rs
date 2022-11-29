/// Common authentication and authorisation mechanisms
pub mod auth;
/// Common configuration mechanisms
pub mod config;
/// Error type with responder implementation
pub mod error;
/// JWT signing functionality
pub mod jwt;
#[cfg(feature = "session_db")]
/// Database manipulation code for keeping track of sessions based on platform tokens
pub mod session;
/// Tera templates
pub mod templates;
/// Translation messages and request guard
pub mod translations;
/// Common types
pub mod types;
/// Utilities
pub mod util;
// credential collection and rendering
#[cfg(feature = "platform_token")]
pub mod credentials;
#[macro_use]
extern crate lazy_static;

pub mod prelude {
    pub use crate::auth::{render_login, render_unauthorized, AuthProvider, Authorized, LoginUrl};
    pub use crate::config::Config;
    pub use crate::error::Error;
    pub use crate::jwt::sign_auth_select_params;
    #[cfg(feature = "session_db")]
    pub use crate::session::{Session, SessionDBConn};
    pub use crate::types::StartRequest;
    pub use crate::types::{AuthSelectParams, Credentials, GuestAuthResult};
    pub use crate::util::random_string;

    #[cfg(feature = "session_db")]
    pub use crate::credentials::get_credentials_for_host;
    #[cfg(feature = "platform_token")]
    pub use crate::credentials::{collect_credentials, render_credentials};
    #[cfg(feature = "platform_token")]
    pub use crate::types::{FromPlatformJwt, GuestToken, HostToken};
}
