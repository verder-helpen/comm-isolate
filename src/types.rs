use core::str;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StartRequest {
    pub purpose: String,
    pub auth_method: String,
}

/// Parameters expected by the auth-select widget
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSelectParams {
    /// The session purpose
    pub purpose: String,
    /// The start url to redirect the user to on authentication success
    pub start_url: String,
    /// The url to redirect the user to on cancel of the login
    pub cancel_url: String,
    /// The communication method's display name
    pub display_name: String,
}

#[derive(Serialize, Debug)]
pub struct GuestAuthResult {
    pub purpose: Option<String>,
    pub name: Option<String>,
    pub auth_result: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Credentials {
    pub purpose: Option<String>,
    pub name: Option<String>,
    pub attributes: Option<HashMap<String, String>>,
}

#[cfg(feature = "platform_token")]
pub use platform_token::*;

#[cfg(feature = "platform_token")]
pub mod platform_token {
    use core::str;

    use josekit::{jws::JwsVerifier, jwt::JwtPayloadValidator};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::jwt::JwtError;

    #[derive(Deserialize, Debug)]
    pub struct HostToken {
        #[serde(rename = "roomId")]
        pub room_id: String,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct GuestToken {
        pub id: String,
        #[serde(rename = "redirectUrl")]
        pub redirect_url: String,
        pub name: String,
        #[serde(rename = "roomId")]
        pub room_id: String,
        pub purpose: String,
    }

    pub trait FromPlatformJwt: Sized + DeserializeOwned {
        fn from_platform_jwt(jwt: &str, verifier: &dyn JwsVerifier) -> Result<Self, JwtError> {
            from_platform_jwt_inner::<Self>(jwt, verifier, std::time::SystemTime::now())
        }
    }

    pub(super) fn from_platform_jwt_inner<T: DeserializeOwned>(
        jwt: &str,
        verifier: &dyn JwsVerifier,
        time: std::time::SystemTime,
    ) -> Result<T, JwtError> {
        let (payload, _) = josekit::jwt::decode_with_verifier(jwt, verifier)?;
        let mut validator = JwtPayloadValidator::new();
        validator.set_base_time(time);
        validator.validate(&payload)?;
        let claim = payload
            .claim("payload")
            .ok_or(JwtError::InvalidStructure("payload"))?;
        let payload = serde_json::from_value(claim.clone())?;
        Ok(payload)
    }

    impl FromPlatformJwt for GuestToken {}

    impl FromPlatformJwt for HostToken {}
}

#[cfg(test)]
mod tests {
    use josekit::jws::alg::hmac::HmacJwsAlgorithm;

    const GUEST_SECRET: &str = "9e4ed6fdc6f7b8fb78f500d3abf3a042412140703249e2fe5671ecdab7e694bb";
    const HOST_SECRET: &str = "54f0a09305eaa1d3ffc3ccb6035e95871eecbfa964404332ffddad52d43bf7b1";

    const GUEST_TOKEN: &str = "\
                            eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                            eyJleHAiOjE2NTQzNTY1MTgsImlhdCI6MTYzM\
                            jM4Njk1MywicGF5bG9hZCI6eyJkb21haW4iOi\
                            JndWVzdCIsImlkIjoiMTAxLTEwMTAtMTAxMC0\
                            xMDEiLCJpbnN0YW5jZSI6InR3ZWVkZWdvbGYu\
                            bmwiLCJuYW1lIjoiVW5rbm93biIsInB1cnBvc\
                            2UiOiJ0ZXN0IiwicmVkaXJlY3RVcmwiOiJodH\
                            RwczovL3R3ZWVkZWdvbGYubmwiLCJyb29tSWQ\
                            iOiIxNiJ9LCJyZWMiOiJJZENvbnRhY3RDb21t\
                            dW5pY2F0aW9uIn0.s-mRc0sOXao-R6pMG15en\
                            Xidwh5PdnK_XwFZkpgS-wo";

    const HOST_TOKEN: &str = "\
                            eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
                            eyJleHAiOjE2MjAyMDk5MDUsImlhdCI6MTYzM\
                            jM4NzExMywicGF5bG9hZCI6eyJkb21haW4iOi\
                            J1c2VyIiwiaWQiOiIxIiwiaW5zdGFuY2UiOiJ\
                            0d2VlZGVnb2xmLm5sIiwicm9vbUlkIjoiMTYi\
                            fSwicmVjIjoiSWRDb250YWN0Q29tbXVuaWNhd\
                            GlvbiJ9.s2qV6zwaH09ktbAxU-YiL-Y5u-AD8R\
                            LiNWrnap7jhJk";

    #[test]
    #[cfg(feature = "platform_token")]
    fn from_platform_jwt_test() {
        use super::platform_token::{GuestToken, HostToken};

        let guest_validator = HmacJwsAlgorithm::Hs256
            .verifier_from_bytes(GUEST_SECRET)
            .unwrap();
        let host_validator = HmacJwsAlgorithm::Hs256
            .verifier_from_bytes(HOST_SECRET)
            .unwrap();

        let GuestToken {
            id,
            redirect_url,
            name,
            room_id,
            purpose: _,
        } = super::platform_token::from_platform_jwt_inner::<GuestToken>(
            GUEST_TOKEN,
            &guest_validator,
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1640000000),
        )
        .expect("Error verifying guest token");

        assert_eq!(id, "101-1010-1010-101");
        assert_eq!(redirect_url, "https://tweedegolf.nl");
        assert_eq!(name, "Unknown");
        assert_eq!(room_id, "16");

        assert!(
            super::platform_token::from_platform_jwt_inner::<GuestToken>(
                GUEST_TOKEN,
                &guest_validator,
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1660000000),
            )
            .is_err()
        );

        let HostToken { room_id } = super::platform_token::from_platform_jwt_inner::<HostToken>(
            HOST_TOKEN,
            &host_validator,
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1620000000),
        )
        .expect("Error verifying host token");

        assert_eq!(room_id, "16");

        assert!(super::platform_token::from_platform_jwt_inner::<HostToken>(
            HOST_TOKEN,
            &host_validator,
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1630000000),
        )
        .is_err());
    }
}
