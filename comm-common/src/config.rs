use crate::auth;
use crate::error::Error;

use josekit::{jwe::JweDecrypter, jws::JwsVerifier};
use serde::Deserialize;
use std::{collections::HashMap, convert::TryFrom};
use verder_helpen_jwt::{EncryptionKeyConfig, SignKeyConfig};

#[cfg(feature = "auth_during_comm")]
pub(crate) use self::auth_during_comm::{AuthDuringCommConfig, RawAuthDuringCommConfig};

pub type LanguageTranslations = HashMap<String, HashMap<String, String>>;

/// Configuration parameters as read directly from config.toml file.
#[derive(Deserialize, Debug)]
pub struct RawConfig {
    /// Internal-facing URL
    internal_url: String,
    /// External-facing URLs. Defaults to Internal-facing if not set
    external_guest_url: Option<String>,
    external_host_url: Option<String>,
    /// Sentry DSN
    sentry_dsn: Option<String>,
    /// Default locale
    default_locale: String,
    /// Translations indexed by locale
    translations: LanguageTranslations,

    /// Private key used to decrypt Verder Helpen JWEs
    decryption_privkey: EncryptionKeyConfig,
    /// Public key used to verify Verder Helpen JWSs
    signature_pubkey: SignKeyConfig,

    auth_provider: Option<String>,
    host_ip_header: Option<String>,

    #[cfg(feature = "auth_during_comm")]
    #[serde(flatten)]
    /// Configuration specific for auth during comm
    auth_during_comm_config: RawAuthDuringCommConfig,
}

/// configuration container for a typical verder-helpen communication plugin
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    pub internal_url: String,
    pub external_guest_url: Option<String>,
    pub external_host_url: Option<String>,
    pub sentry_dsn: Option<String>,
    pub default_locale: String,
    pub translations: LanguageTranslations,

    pub decrypter: Box<dyn JweDecrypter>,
    pub verifier: Box<dyn JwsVerifier>,

    pub auth_provider: Option<auth::AuthProvider>,
    pub host_ip_header: Option<String>,

    #[cfg(feature = "auth_during_comm")]
    #[serde(flatten)]
    pub auth_during_comm_config: AuthDuringCommConfig,
}

// This tryfrom can be removed once try_from for fields lands in serde
impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(raw_config: RawConfig) -> Result<Config, Error> {
        #[cfg(feature = "auth_during_comm")]
        let auth_during_comm_config =
            AuthDuringCommConfig::try_from(raw_config.auth_during_comm_config)?;

        let auth_provider = match raw_config.auth_provider {
            Some(a) => Some(auth::AuthProvider::try_from(a)?),
            None => None,
        };

        Ok(Config {
            #[cfg(feature = "auth_during_comm")]
            auth_during_comm_config,
            internal_url: raw_config.internal_url,
            external_guest_url: raw_config.external_guest_url,
            external_host_url: raw_config.external_host_url,
            sentry_dsn: raw_config.sentry_dsn,
            default_locale: raw_config.default_locale,
            translations: raw_config.translations,
            auth_provider,
            host_ip_header: raw_config.host_ip_header,
            decrypter: Box::<dyn JweDecrypter>::try_from(raw_config.decryption_privkey)?,
            verifier: Box::<dyn JwsVerifier>::try_from(raw_config.signature_pubkey)?,
        })
    }
}

impl Config {
    pub fn decrypter(&self) -> &dyn JweDecrypter {
        self.decrypter.as_ref()
    }

    pub fn verifier(&self) -> &dyn JwsVerifier {
        self.verifier.as_ref()
    }

    pub fn internal_url(&self) -> &str {
        &self.internal_url
    }

    pub fn external_guest_url(&self) -> &str {
        match &self.external_guest_url {
            Some(external_guest_url) => external_guest_url,
            None => &self.internal_url,
        }
    }

    pub fn external_host_url(&self) -> &str {
        match &self.external_host_url {
            Some(external_host_url) => external_host_url,
            None => &self.internal_url,
        }
    }

    pub fn sentry_dsn(&self) -> Option<&str> {
        self.sentry_dsn.as_deref()
    }

    pub fn get_language_translations(&self) -> &LanguageTranslations {
        &self.translations
    }

    pub fn auth_provider(&self) -> &Option<auth::AuthProvider> {
        &self.auth_provider
    }

    pub fn host_ip_header(&self) -> Option<&str> {
        self.host_ip_header.as_deref()
    }

    #[cfg(feature = "auth_during_comm")]
    pub fn auth_during_comm_config(&self) -> &AuthDuringCommConfig {
        &self.auth_during_comm_config
    }
}

#[cfg(feature = "auth_during_comm")]
mod auth_during_comm {
    use serde::Deserialize;
    use std::{convert::TryFrom, fmt::Debug};
    use verder_helpen_jwt::SignKeyConfig;

    use josekit::jws::{alg::hmac::HmacJwsAlgorithm, JwsSigner, JwsVerifier};

    use crate::error::Error;

    #[derive(Deserialize)]
    #[serde(from = "String")]
    struct TokenSecret(String);

    impl From<String> for TokenSecret {
        fn from(value: String) -> Self {
            TokenSecret(value)
        }
    }

    impl Debug for TokenSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TokenSecret").finish()
        }
    }

    #[derive(Deserialize, Debug)]
    /// Configuration specific for auth during comm
    pub struct RawAuthDuringCommConfig {
        /// URL to reach the Verder Helpen core directly
        core_url: String,
        /// URL to allow user redirects to the widget
        widget_url: String,
        /// Display name for this plugin, to be presented to user
        display_name: String,
        /// Private key to sign widget parameters
        widget_signing_privkey: SignKeyConfig,
        /// Private key to sign start authenticate requests
        start_auth_signing_privkey: SignKeyConfig,
        /// Key Identifier of start authentication key
        start_auth_key_id: String,
        /// Secret for verifying guest tokens
        guest_signature_secret: TokenSecret,
        /// Secret for verifying host tokens
        host_signature_secret: TokenSecret,
    }

    #[derive(Debug, Deserialize)]
    #[serde(try_from = "RawAuthDuringCommConfig")]
    pub struct AuthDuringCommConfig {
        pub(crate) core_url: String,
        pub(crate) widget_url: String,
        pub(crate) display_name: String,
        pub(crate) widget_signer: Box<dyn JwsSigner>,
        pub(crate) start_auth_signer: Box<dyn JwsSigner>,
        pub(crate) start_auth_key_id: String,
        pub(crate) guest_verifier: Box<dyn JwsVerifier>,
        pub(crate) host_verifier: Box<dyn JwsVerifier>,
    }

    // This tryfrom can be removed once try_from for fields lands in serde
    impl TryFrom<RawAuthDuringCommConfig> for AuthDuringCommConfig {
        type Error = Error;
        fn try_from(raw_config: RawAuthDuringCommConfig) -> Result<AuthDuringCommConfig, Error> {
            let guest_verifier = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(raw_config.guest_signature_secret.0)
                .unwrap();
            let host_verifier = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(raw_config.host_signature_secret.0)
                .unwrap();

            Ok(AuthDuringCommConfig {
                core_url: raw_config.core_url,
                widget_url: raw_config.widget_url,
                display_name: raw_config.display_name,

                widget_signer: Box::<dyn JwsSigner>::try_from(raw_config.widget_signing_privkey)?,
                start_auth_signer: Box::<dyn JwsSigner>::try_from(
                    raw_config.start_auth_signing_privkey,
                )?,
                start_auth_key_id: raw_config.start_auth_key_id,
                guest_verifier: Box::new(guest_verifier),
                host_verifier: Box::new(host_verifier),
            })
        }
    }

    impl AuthDuringCommConfig {
        pub fn core_url(&self) -> &str {
            &self.core_url
        }

        pub fn widget_url(&self) -> &str {
            &self.widget_url
        }

        pub fn display_name(&self) -> &str {
            &self.display_name
        }

        pub fn widget_signer(&self) -> &dyn JwsSigner {
            self.widget_signer.as_ref()
        }

        pub fn start_auth_signer(&self) -> &dyn JwsSigner {
            self.start_auth_signer.as_ref()
        }

        pub fn start_auth_key_id(&self) -> &str {
            &self.start_auth_key_id
        }

        pub fn guest_verifier(&self) -> &dyn JwsVerifier {
            self.guest_verifier.as_ref()
        }

        pub fn host_verifier(&self) -> &dyn JwsVerifier {
            self.host_verifier.as_ref()
        }
    }

    #[cfg(test)]
    mod tests {
        use josekit::jws::alg::hmac::HmacJwsAlgorithm;

        use super::TokenSecret;

        #[test]
        fn test_log_hiding() {
            let test_secret = TokenSecret("test1234123412341234123412341234".into());
            assert_eq!(format!("{:?}", test_secret), "TokenSecret");

            // Cannary test for something going wrong in the jose library
            let test_verifier = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(test_secret.0)
                .unwrap();
            assert_eq!(format!("{:?}", test_verifier), "HmacJwsVerifier { algorithm: Hs256, private_key: PKey { algorithm: \"HMAC\" }, key_id: None }");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use figment::providers::{Format, Toml};
    use rocket::figment::Figment;

    const TEST_CONFIG_VALID: &str = r#"
[global]
internal_url = "https://internal.example.com"
external_guest_url = "https://external.example.com/guest"
external_host_url = "https://external.example.com/host"
default_locale = "en"

core_url = "https://core.example.com"
widget_url = "https://widget.example.com"
display_name = "Example Comm"
auth_provider = "Google"
guest_signature_secret = "fliepfliepfliepfliepfliepfliepfliepfliep"
host_signature_secret = "flapflapflapflapflapflapflapflapflapflap"
start_auth_key_id = "example"

[global.translations.en]
unknown_error = "Unknown error"

[global.translations.nl]
unknown_error = "Onbekende fout"

[global.widget_signing_privkey]
type = "EC"
key = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJdHGkAfKUVshsNPQ
5UA9sNCf74eALrLrtBQE1nDFlv+hRANCAARkuq4SKMntw/sr2ogcbsS8JOmHnc3i
fPrU6B65lZ28zsvIFVe5bnedj5vo0maimGBxkerNKItuT6M+8ga9VTHN
-----END PRIVATE KEY-----
"""

[global.start_auth_signing_privkey]
type = "EC"
key = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJdHGkAfKUVshsNPQ
5UA9sNCf74eALrLrtBQE1nDFlv+hRANCAARkuq4SKMntw/sr2ogcbsS8JOmHnc3i
fPrU6B65lZ28zsvIFVe5bnedj5vo0maimGBxkerNKItuT6M+8ga9VTHN
-----END PRIVATE KEY-----
"""

[global.decryption_privkey]
type = "EC"
key = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJdHGkAfKUVshsNPQ
5UA9sNCf74eALrLrtBQE1nDFlv+hRANCAARkuq4SKMntw/sr2ogcbsS8JOmHnc3i
fPrU6B65lZ28zsvIFVe5bnedj5vo0maimGBxkerNKItuT6M+8ga9VTHN
-----END PRIVATE KEY-----
"""

[global.signature_pubkey]
type = "EC"
key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZLquEijJ7cP7K9qIHG7EvCTph53N
4nz61OgeuZWdvM7LyBVXuW53nY+b6NJmophgcZHqzSiLbk+jPvIGvVUxzQ==
-----END PUBLIC KEY-----
"""

"#;

    fn config_from_str(config: &str) -> Config {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(config).nested());

        figment.extract::<Config>().unwrap()
    }

    #[test]
    fn test_valid_config() {
        let config: Config = config_from_str(TEST_CONFIG_VALID);

        assert_eq!(config.internal_url(), "https://internal.example.com");
        assert_eq!(
            config.external_guest_url(),
            "https://external.example.com/guest"
        );
        assert_eq!(
            config.external_host_url(),
            "https://external.example.com/host"
        );

        #[cfg(feature = "auth_during_comm")]
        {
            assert_eq!(
                config.auth_during_comm_config().core_url(),
                "https://core.example.com"
            );
            assert_eq!(
                config.auth_during_comm_config().display_name(),
                "Example Comm"
            );

            let message: [u8; 3] = [42, 42, 42];

            let auth_during_comm_signature = config
                .auth_during_comm_config()
                .start_auth_signer()
                .sign(&message)
                .unwrap();

            assert!(config
                .verifier()
                .verify(&message, &auth_during_comm_signature)
                .is_ok());

            let widget_signing_signature = config
                .auth_during_comm_config()
                .widget_signer()
                .sign(&message)
                .unwrap();

            assert!(config
                .verifier()
                .verify(&message, &widget_signing_signature)
                .is_ok());
        }
    }
}
