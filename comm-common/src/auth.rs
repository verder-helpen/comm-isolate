use std::{convert::TryFrom, str::FromStr};

use crate::error::Error;
use crate::templates::{RenderType, RenderedContent, TEMPLATES};
use crate::{config::Config, translations::Translations};

use reqwest::header::AUTHORIZATION;
use rocket::{
    fairing::{AdHoc, Fairing},
    http::{Cookie, CookieJar, SameSite, Status},
    outcome::Outcome,
    request::{self, FromRequest, Request},
    response::Redirect,
    State,
};
use rocket_oauth2::{OAuth2, TokenResponse};
use serde::{Deserialize, Serialize};
use tera::Context;

#[derive(Deserialize, Serialize)]
pub struct LoginUrl {
    pub login_url: String,
}

#[derive(Debug, strum_macros::EnumString)]
pub enum AuthProvider {
    Google,
    Microsoft,
}

impl AuthProvider {
    pub fn fairing(&self) -> impl Fairing {
        match self {
            AuthProvider::Google => AdHoc::on_ignite("Auth", |rocket| async {
                rocket
                    .mount(
                        "/host",
                        rocket::routes![login_google, redirect_google, logout_generic,],
                    )
                    .attach(OAuth2::<Google>::fairing("google"))
            }),
            AuthProvider::Microsoft => AdHoc::on_ignite("Auth", |rocket| async {
                rocket
                    .mount(
                        "/host",
                        rocket::routes![login_microsoft, redirect_microsoft, logout_generic,],
                    )
                    .attach(OAuth2::<Microsoft>::fairing("microsoft"))
            }),
        }
    }

    pub async fn check_token(
        &self,
        token: &TokenCookie,
        source_ip: SourceIP<'_>,
    ) -> Result<bool, Error> {
        match self {
            AuthProvider::Google => check_token_google(token, source_ip).await,
            AuthProvider::Microsoft => check_token_microsoft(token, source_ip).await,
        }
    }
}

impl TryFrom<String> for AuthProvider {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Ok(AuthProvider::from_str(&name)?)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SourceIP<'r>(&'r str);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SourceIP<'r> {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<SourceIP<'r>, Error> {
        let config = request.rocket().state::<Config>().unwrap(); // if we don't have a config, panic

        if let Some(header_name) = config.host_ip_header() {
            match request
                .headers()
                .get_one(header_name)
                .and_then(|v| v.split(',').rev().nth(1))
            {
                Some(v) => Outcome::Success(SourceIP(v)),
                None => {
                    Outcome::Failure((Status::BadRequest, Error::BadRequest("missing ip header")))
                }
            }
        } else {
            Outcome::Success(SourceIP(""))
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenCookie {
    token: String,
    ip: String,
}

impl TokenCookie {
    fn new<T>(token: TokenResponse<T>, ip: SourceIP) -> Self {
        TokenCookie {
            token: token.access_token().to_owned(),
            ip: ip.0.to_owned(),
        }
    }

    // To string is not intended for display purposes.
    #[allow(clippy::inherent_to_string)]
    fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap() // cant fail
    }
}

impl FromStr for TokenCookie {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        serde_json::from_str(s)
    }
}

pub struct Authorized(bool);

impl From<Authorized> for bool {
    fn from(authorized: Authorized) -> Self {
        authorized.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorized {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Authorized, Error> {
        let config = request.rocket().state::<Config>().unwrap(); // if we don't have a config, panic

        let source_ip = match SourceIP::from_request(request).await {
            Outcome::Success(v) => v,
            Outcome::Failure(v) => return Outcome::Failure(v),
            Outcome::Forward(_) => {
                return Outcome::Failure((
                    Status::InternalServerError,
                    Error::Forbidden("Error validating token cookie".to_owned()),
                ))
            }
        };

        match config.auth_provider() {
            Some(auth_provider) => match request.cookies().get_private("token") {
                Some(token) => {
                    let authorised = auth_provider
                        .check_token(&token.value().parse().unwrap(), source_ip)
                        .await;
                    match authorised {
                        Ok(true) => Outcome::Success(Authorized(true)),
                        Ok(false) => Outcome::Success(Authorized(false)), // token cookie not valid
                        Err(_) => Outcome::Failure((
                            Status::InternalServerError,
                            Error::Forbidden("Error validating token cookie".to_owned()),
                        )),
                    }
                }
                None => Outcome::Success(Authorized(false)), // no token cookie present
            },
            None => Outcome::Success(Authorized(true)),
        }
    }
}

struct Google;

#[rocket::get("/auth/login")]
fn login_google(cookies: &CookieJar<'_>, oauth2: OAuth2<Google>) -> Redirect {
    oauth2.get_redirect(cookies, &["profile"]).unwrap()
}

#[rocket::get("/auth/redirect")]
async fn redirect_google(
    config: &State<Config>,
    cookies: &CookieJar<'_>,
    token: TokenResponse<Google>,
    source_ip: SourceIP<'_>,
    translations: Translations,
) -> Result<String, Error> {
    redirect_generic(config, cookies, token, source_ip, translations).await
}

#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    #[serde(default)]
    sub: String,
}

// Currently only checks whether we can actually login with the provided cookie
async fn check_token_google(token: &TokenCookie, source_ip: SourceIP<'_>) -> Result<bool, Error> {
    if token.ip != source_ip.0 {
        return Ok(false);
    }

    let user_info: GoogleUserInfo = reqwest::Client::builder()
        .build()?
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .header(AUTHORIZATION, format!("Bearer {}", token.token))
        .send()
        .await?
        .json()
        .await?;

    Ok(!user_info.sub.is_empty())
}

struct Microsoft;

#[rocket::get("/auth/login")]
fn login_microsoft(cookies: &CookieJar<'_>, oauth2: OAuth2<Microsoft>) -> Redirect {
    oauth2.get_redirect(cookies, &["user.read"]).unwrap()
}

#[rocket::get("/auth/redirect")]
async fn redirect_microsoft(
    config: &State<Config>,
    cookies: &CookieJar<'_>,
    token: TokenResponse<Microsoft>,
    source_ip: SourceIP<'_>,
    translations: Translations,
) -> Result<String, Error> {
    redirect_generic(config, cookies, token, source_ip, translations).await
}

#[derive(serde::Deserialize)]
struct MicrosoftUserInfo {
    #[serde(default, rename = "displayName")]
    display_name: String,
}

// Currently only checks whether we can actually login with the provided cookie
async fn check_token_microsoft(
    token: &TokenCookie,
    source_ip: SourceIP<'_>,
) -> Result<bool, Error> {
    if token.ip != source_ip.0 {
        return Ok(false);
    }

    let user_info: MicrosoftUserInfo = reqwest::Client::builder()
        .build()?
        .get("https://graph.microsoft.com/v1.0/me")
        .header(AUTHORIZATION, format!("Bearer {}", token.token))
        .send()
        .await?
        .json()
        .await?;

    Ok(!user_info.display_name.is_empty())
}

async fn redirect_generic<T>(
    config: &State<Config>,
    cookies: &CookieJar<'_>,
    token: TokenResponse<T>,
    source_ip: SourceIP<'_>,
    translations: Translations,
) -> Result<String, Error> {
    let proposed_token = TokenCookie::new(token, source_ip);
    if let Some(auth_provider) = config.auth_provider() {
        if auth_provider
            .check_token(&proposed_token, source_ip)
            .await?
        {
            cookies.add_private(
                Cookie::build("token", proposed_token.to_string())
                    .http_only(true)
                    .secure(true)
                    .same_site(SameSite::None)
                    .finish(),
            );

            return Ok(translations.get(
                "login_successful",
                "You are now logged in. You can close this window",
            ));
        }

        return Err(Error::Forbidden(translations.get(
            "insufficient_permissions",
            "Insufficient permissions, try logging in with another account",
        )));
    }

    Err(Error::InternalServer(translations.get(
        "no_authentication_provider",
        "No authentication provider configured.",
    )))
}

#[rocket::post("/auth/logout")]
async fn logout_generic(
    cookies: &CookieJar<'_>,
    translations: Translations,
) -> Result<String, Error> {
    cookies.remove_private(Cookie::named("token"));

    Ok(translations.get(
        "logout_successful",
        "You are now logged out. You can close this window",
    ))
}

pub fn render_login(
    config: &Config,
    render_type: RenderType,
    translations: Translations,
) -> Result<RenderedContent, Error> {
    let login_url = format!("{}/auth/login", config.external_host_url());

    if render_type == RenderType::Html {
        let mut context = Context::new();

        context.insert("translations", translations.all());
        context.insert("login_url", &login_url);

        let content = TEMPLATES.render("login.html", &context)?;
        return Ok(RenderedContent {
            content,
            render_type,
        });
    }

    Err(Error::Unauthorized(login_url))
}

pub fn render_unauthorized(
    config: &Config,
    render_type: RenderType,
    translations: Translations,
) -> Result<RenderedContent, Error> {
    let logout_url = format!("{}/auth/logout", config.external_host_url());

    if render_type == RenderType::Html {
        let mut context = Context::new();

        context.insert("translations", translations.all());
        context.insert("logout_url", &logout_url);

        let content = TEMPLATES.render("expired.html", &context)?;
        return Ok(RenderedContent {
            content,
            render_type,
        });
    }

    Err(Error::Forbidden(logout_url))
}

pub fn render_not_found(
    config: &Config,
    render_type: RenderType,
    translations: Translations,
) -> Result<RenderedContent, Error> {
    let logout_url = format!("{}/auth/logout", config.external_host_url());

    if render_type == RenderType::Html {
        let mut context = Context::new();

        context.insert("translations", translations.all());
        context.insert("logout_url", &logout_url);

        let content = TEMPLATES.render("not_found.html", &context)?;
        return Ok(RenderedContent {
            content,
            render_type,
        });
    }

    Err(Error::NotFound)
}
