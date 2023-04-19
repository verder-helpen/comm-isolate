use serde::Serialize;
use serde_json;
use tera::Context;

#[cfg(feature = "session_db")]
use crate::session::{Session, SessionDBConn};
#[cfg(feature = "session_db")]
use crate::types::platform_token::{FromPlatformJwt, HostToken};
use crate::{
    config::Config,
    error::Error,
    templates::{RenderType, RenderedContent, TEMPLATES},
    translations::Translations,
    types::{Credentials, GuestAuthResult},
};

/// convert a list of guest jwt's to a list of credentials
pub fn collect_credentials(
    guest_auth_results: &[GuestAuthResult],
    config: &Config,
) -> Result<Vec<Credentials>, Error> {
    let mut credentials: Vec<Credentials> = vec![];

    for guest_auth_result in guest_auth_results.iter() {
        if let Some(result) = &guest_auth_result.auth_result {
            if let Some(attributes) =
                verder_helpen_jwt::dangerous_decrypt_auth_result_without_verifying_expiration(
                    result,
                    config.verifier(),
                    config.decrypter(),
                )?
                .attributes
            {
                credentials.push(Credentials {
                    name: guest_auth_result.name.clone(),
                    purpose: guest_auth_result.purpose.clone(),
                    attributes,
                });
            }
        };
    }

    Ok(credentials)
}

#[derive(Serialize)]
pub struct SortedCredentials {
    pub purpose: Option<String>,
    pub name: Option<String>,
    pub attributes: Vec<(String, String)>,
}

/// sorted credentials are sorted by their name (key)
impl From<Credentials> for SortedCredentials {
    fn from(credentials: Credentials) -> Self {
        let mut attributes = credentials
            .attributes
            .into_iter()
            .collect::<Vec<(String, String)>>();

        attributes.sort_by(|x, y| x.0.cmp(&y.0));

        SortedCredentials {
            purpose: credentials.purpose,
            name: credentials.name,
            attributes,
        }
    }
}

/// render a list of users and credentials to html or json
pub fn render_credentials(
    credentials: Vec<Credentials>,
    render_type: RenderType,
    translations: Translations,
) -> Result<RenderedContent, Error> {
    if render_type == RenderType::Json {
        let content = serde_json::to_string(&credentials)?;
        return Ok(RenderedContent {
            content,
            render_type,
        });
    }

    let mut context = Context::new();

    let sorted_credentials: Vec<SortedCredentials> = credentials
        .into_iter()
        .map(SortedCredentials::from)
        .collect();

    context.insert("translations", translations.all());
    context.insert("credentials", &sorted_credentials);

    let content = if render_type == RenderType::HtmlPage {
        TEMPLATES.render("base.html", &context)?
    } else {
        TEMPLATES.render("credentials.html", &context)?
    };

    Ok(RenderedContent {
        content,
        render_type,
    })
}

/// retrieve sessions for all users in a room
/// the id of the room is provided by a host jwt
#[cfg(feature = "session_db")]
pub async fn get_sessions_for_host(
    host_token: String,
    config: &Config,
    db: &SessionDBConn,
) -> Result<Vec<Session>, Error> {
    let host_token = HostToken::from_platform_jwt(
        &host_token,
        config.auth_during_comm_config().host_verifier(),
    )?;

    Session::find_by_room_id(host_token.room_id, db).await
}

/// retrieve authentication results for all users in a room
/// the id of the room is provided by a host jwt
#[cfg(feature = "session_db")]
pub async fn get_credentials_for_host(
    host_token: String,
    config: &Config,
    db: &SessionDBConn,
) -> Result<Vec<Credentials>, Error> {
    let sessions = get_sessions_for_host(host_token, config, db).await?;
    for session in &sessions {
        session.mark_active(db).await?;
    }

    let guest_auth_results = sessions
        .into_iter()
        .map(|session: Session| GuestAuthResult {
            purpose: Some(session.guest_token.purpose),
            name: Some(session.guest_token.name),
            auth_result: session.auth_result,
        })
        .collect::<Vec<GuestAuthResult>>();

    collect_credentials(&guest_auth_results, config)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, convert::TryFrom};

    use josekit::{
        jwe::{JweDecrypter, JweEncrypter},
        jws::{alg::hmac::HmacJwsAlgorithm, JwsSigner, JwsVerifier},
    };
    use verder_helpen_jwt::{sign_and_encrypt_auth_result, EncryptionKeyConfig, SignKeyConfig};
    use verder_helpen_proto::{AuthResult, AuthStatus};

    use super::*;
    use crate::config::AuthDuringCommConfig;

    const EC_PUBKEY: &str = r"
    type: EC
    key: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZLquEijJ7cP7K9qIHG7EvCTph53N
        4nz61OgeuZWdvM7LyBVXuW53nY+b6NJmophgcZHqzSiLbk+jPvIGvVUxzQ==
        -----END PUBLIC KEY-----
    ";

    const EC_PRIVKEY: &str = r"
    type: EC
    key: |
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJdHGkAfKUVshsNPQ
        5UA9sNCf74eALrLrtBQE1nDFlv+hRANCAARkuq4SKMntw/sr2ogcbsS8JOmHnc3i
        fPrU6B65lZ28zsvIFVe5bnedj5vo0maimGBxkerNKItuT6M+8ga9VTHN
        -----END PRIVATE KEY-----
    ";
    const HOST_SECRET: &str = "54f0a09305eaa1d3ffc3ccb6035e95871eecbfa964404332ffddad52d43bf7b1";
    const GUEST_SECRET: &str = "9e4ed6fdc6f7b8fb78f500d3abf3a042412140703249e2fe5671ecdab7e694bb";

    fn remove_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn render_credentials_test() {
        let enc_config: EncryptionKeyConfig = serde_yaml::from_str(EC_PUBKEY).unwrap();
        let dec_config: EncryptionKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();

        let decrypter = Box::<dyn JweDecrypter>::try_from(dec_config).unwrap();
        let encrypter = Box::<dyn JweEncrypter>::try_from(enc_config).unwrap();

        let sig_config: SignKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();
        let ver_config: SignKeyConfig = serde_yaml::from_str(EC_PUBKEY).unwrap();
        let widget_sig_config: SignKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();

        let signer = Box::<dyn JwsSigner>::try_from(sig_config).unwrap();
        let verifier = Box::<dyn JwsVerifier>::try_from(ver_config).unwrap();

        let widget_signer = Box::<dyn JwsSigner>::try_from(widget_sig_config).unwrap();
        let start_auth_signer = widget_signer.clone();
        let guest_verifier = HmacJwsAlgorithm::Hs256
            .verifier_from_bytes(GUEST_SECRET)
            .unwrap();
        let host_verifier = HmacJwsAlgorithm::Hs256
            .verifier_from_bytes(HOST_SECRET)
            .unwrap();

        let mut test_attributes: HashMap<String, String> = HashMap::new();

        test_attributes.insert("age".to_string(), "42".to_string());
        test_attributes.insert("email".to_string(), "hd@example.com".to_string());

        let in_result = AuthResult {
            status: AuthStatus::Success,
            attributes: Some(test_attributes),
            session_url: None,
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref()).unwrap();

        let guest_auth_results = vec![GuestAuthResult {
            purpose: Some("test_purpose".to_string()),
            name: Some("Henk Dieter".to_string()),
            auth_result: Some(jwe),
        }];

        let auth_during_comm_config = AuthDuringCommConfig {
            core_url: "https://example.com".to_string(),
            widget_url: "https://example.com".to_string(),
            display_name: "comm-common".to_string(),
            widget_signer,
            start_auth_signer,
            start_auth_key_id: "not-needed".into(),
            guest_verifier: Box::new(guest_verifier),
            host_verifier: Box::new(host_verifier),
        };

        let config: Config = Config {
            internal_url: "https://example.com".to_string(),
            external_host_url: None,
            external_guest_url: None,
            sentry_dsn: None,
            default_locale: String::from("nl"),
            translations: HashMap::new(),
            decrypter,
            auth_provider: None,
            verifier,
            auth_during_comm_config,
        };

        let translations = Translations {
            translations: HashMap::from([
                ("attributes".to_string(), "Gegevens".to_string()),
                ("title".to_string(), "Gegevens".to_string()),
                ("age".to_string(), "Leeftijd".to_string()),
                ("email".to_string(), "E-mailadres".to_string()),
            ]),
            language: "nl".to_string(),
        };

        let credentials = collect_credentials(&guest_auth_results, &config).unwrap();
        let out_result =
            render_credentials(credentials, RenderType::Html, translations.clone()).unwrap();
        let result: &str = "<sectionclass=\"credentials\"><h4>HenkDieter</\
                            h4><dl><dt><span>Leeftijd</span></dt><dd><span>42</span></\
                            dd><dt><span>E-mailadres</span></dt><dd><span>hd@example.com</span></\
                            dd></dl></section>";

        assert_eq!(
            remove_whitespace(result),
            remove_whitespace(out_result.content())
        );

        let credentials = collect_credentials(&guest_auth_results, &config).unwrap();
        let out_result =
            render_credentials(credentials, RenderType::HtmlPage, translations.clone()).unwrap();
        let result: &str = "<!doctypehtml><htmllang=\"en\"><head><metacharset=\"utf-8\"\
                            ><metaname=\"viewport\"content=\"width=device-width,initial-scale=1\"\
                            ><title>Gegevens</title></head><body><main><divclass=\"attributes\"\
                            ><div><h4>Gegevens</h4><sectionclass=\"credentials\"><h4>HenkDieter</\
                            h4><dl><dt><span>Leeftijd</span></dt><dd><span>42</span></\
                            dd><dt><span>E-mailadres</span></dt><dd><span>hd@example.com</span></\
                            dd></dl></section></div></div></main></body></html>";

        assert_eq!(
            remove_whitespace(result),
            remove_whitespace(out_result.content())
        );

        let credentials = collect_credentials(&guest_auth_results, &config).unwrap();
        let rendered = render_credentials(credentials, RenderType::Json, translations).unwrap();
        let result: serde_json::Value = serde_json::from_str(rendered.content()).unwrap();
        let expected = serde_json::json! {
            [{
                "purpose":"test_purpose",
                "name":"Henk Dieter",
                "attributes":{"age":"42","email":"hd@example.com"}}
            ]
        };

        assert_eq!(result, expected);
    }
}
