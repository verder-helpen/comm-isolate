#[macro_use]
extern crate lazy_static;

use std::convert::Infallible;

use auth::Authorized;
use config::Config;
use error::Error;
use rocket::{
    get, post,
    response::{
        content::{RawCss, RawJavaScript},
        stream::{Event, EventStream},
        Redirect,
    },
    routes,
    serde::{json::Json, Deserialize, Serialize},
    tokio::{
        select,
        sync::broadcast::{channel, error::RecvError, Sender},
    },
    Shutdown, State,
};
use session::{Session, SessionDBConn};
use templates::{RenderType, RenderedContent};
use translations::Translations;
use types::{AuthSelectParams, FromPlatformJwt, GuestToken, HostToken, StartRequest};
use verder_helpen_proto::{ClientUrlResponse, StartRequestAuthOnly};

mod auth;
mod config;
mod credentials;
mod error;
mod jwt;
mod session;
mod templates;
mod translations;
mod types;
mod util;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AttributesUpdateEvent {
    pub attr_id: String,
}

#[get("/init/<guest_token>")]
async fn init(guest_token: String, config: &State<Config>) -> Result<Redirect, Error> {
    let GuestToken {
        purpose,
        redirect_url,
        ..
    } = GuestToken::from_platform_jwt(
        &guest_token,
        config.auth_during_comm_config().guest_verifier(),
    )?;

    let auth_select_params = AuthSelectParams {
        purpose,
        start_url: format!("{}/start/{}", config.external_guest_url(), guest_token),
        cancel_url: redirect_url,
        display_name: config.auth_during_comm_config().display_name().to_owned(),
    };

    let auth_select_params = jwt::sign_auth_select_params(
        auth_select_params,
        config.auth_during_comm_config().widget_signer(),
    )?;
    let uri = format!(
        "{}{}",
        config.auth_during_comm_config().widget_url(),
        auth_select_params
    );

    Ok(Redirect::to(uri))
}

#[post("/start/<guest_token>", data = "<start_request>")]
async fn start(
    guest_token: String,
    start_request: String,
    config: &State<Config>,
    db: SessionDBConn,
    queue: &State<Sender<AttributesUpdateEvent>>,
) -> Result<Json<ClientUrlResponse>, Error> {
    let guest_token = GuestToken::from_platform_jwt(
        &guest_token,
        config.auth_during_comm_config().guest_verifier(),
    )?;
    let StartRequest {
        purpose,
        auth_method,
    } = serde_json::from_str(&start_request)?;

    if purpose != guest_token.purpose {
        return Err(Error::BadRequest(
            "Purpose from start request does not match guest token purpose.",
        ));
    }

    let attr_id = util::random_string(64);
    let comm_url = guest_token.redirect_url.clone();
    let attr_url = format!("{}/auth_result/{}", config.internal_url(), attr_id);
    let purpose = guest_token.purpose.clone();
    if !Session::restart_auth(guest_token.clone(), attr_id.clone(), &db).await? {
        let session = Session::new(guest_token, attr_id.clone());

        session.persist(&db).await?;
    }

    let start_request = StartRequestAuthOnly {
        purpose,
        auth_method,
        comm_url,
        attr_url: Some(attr_url),
    };

    let start_request = jwt::sign_start_auth_request(
        start_request,
        config.auth_during_comm_config().start_auth_key_id(),
        config.auth_during_comm_config().start_auth_signer(),
    )?;

    let client = reqwest::Client::new();
    let client_url_response = client
        .post(format!(
            "{}/start",
            config.auth_during_comm_config().core_url()
        ))
        .header(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        )
        .header(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/jwt"),
        )
        .body(start_request)
        .send()
        .await?
        .text()
        .await?;

    // may fail when there are no subscribers
    let res = queue.send(AttributesUpdateEvent { attr_id });
    match res {
        Ok(_) => println!("Update sent"),
        Err(_) => println!("Err, no update sent"),
    }

    let client_url_response = serde_json::from_str::<ClientUrlResponse>(&client_url_response)?;
    Ok(Json(client_url_response))
}

#[post("/auth_result/<attr_id>", data = "<auth_result>")]
async fn auth_result(
    attr_id: String,
    auth_result: String,
    config: &State<Config>,
    db: SessionDBConn,
    queue: &State<Sender<AttributesUpdateEvent>>,
) -> Result<(), Error> {
    verder_helpen_jwt::decrypt_and_verify_auth_result(
        &auth_result,
        config.verifier(),
        config.decrypter(),
    )?;
    let response = Session::register_auth_result(attr_id.clone(), auth_result, &db).await;

    // may fail when there are no subscribers
    let _ = queue.send(AttributesUpdateEvent { attr_id });

    response
}

struct MyRocket<'a>(&'a rocket::Rocket<rocket::Orbit>);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for MyRocket<'r> {
    type Error = Infallible;

    async fn from_request(
        request: &'r rocket::request::Request<'_>,
    ) -> rocket::request::Outcome<MyRocket<'r>, Infallible> {
        rocket::request::Outcome::Success(MyRocket(request.rocket()))
    }
}

#[get("/live/<token>")]
async fn session_info<'a>(
    queue: &State<Sender<AttributesUpdateEvent>>,
    mut end: Shutdown,
    token: String,
    config: &'a State<Config>,
    authorized: Authorized,
    rocket: MyRocket<'a>,
) -> EventStream![Event + 'a] {
    let mut rx = queue.subscribe();

    EventStream! {
        if authorized.into() {
            let host_token = HostToken::from_platform_jwt(
                &token,
                config.auth_during_comm_config().host_verifier(),
            );

            if let Ok(host_token) = host_token {
                yield Event::data("start");

                loop {
                    select! {
                        msg = rx.recv() => match msg {
                            Ok(msg) => {
                                let db = match SessionDBConn::get_one(rocket.0).await {
                                    Some(db) => db,
                                    None => break,
                                };

                                // fetch all attribute ids related to the provided host token
                                if let Ok(sessions) = Session::find_by_room_id(
                                    host_token.room_id.clone(),
                                    &db
                                ).await {
                                    let attr_ids: Vec<String> = sessions
                                        .iter()
                                        .map(|session: &Session| session.attr_id.clone())
                                        .collect();

                                    if attr_ids.contains(&msg.attr_id) {
                                        yield Event::data("update");
                                    }
                                };
                            },
                            Err(RecvError::Closed) => break,
                            Err(RecvError::Lagged(_)) => continue,
                        },
                        _ = &mut end => break,
                    };
                }
            }
            yield Event::data("badrequest");
        }

        yield Event::data("forbidden");
    }
}

#[get("/clean_db")]
async fn clean_db(db: SessionDBConn) -> Result<(), Error> {
    session::clean_db(&db).await
}

#[get("/<token>")]
async fn attribute_ui(
    config: &State<Config>,
    db: SessionDBConn,
    authorized: Authorized,
    translations: Translations,
    token: String,
) -> Result<RenderedContent, Error> {
    if authorized.into() {
        let host_token =
            HostToken::from_platform_jwt(&token, config.auth_during_comm_config().host_verifier());

        if let Ok(token) = host_token {
            let credentials = credentials::get_credentials_for_host(token, config, &db)
                .await
                .unwrap_or_else(|_| Vec::new());

            return Ok(credentials::render_credentials(
                config,
                credentials,
                RenderType::Html,
                translations,
            )
            .unwrap());
        }

        return Err(Error::BadRequest("invalid host token"));
    }

    auth::render_login(config, RenderType::Html, translations)
}

#[get("/attribute.css")]
async fn attribute_css() -> RawCss<&'static str> {
    RawCss(include_str!("templates/attribute.css"))
}

#[get("/attribute.js")]
async fn attribute_js() -> RawJavaScript<&'static str> {
    RawJavaScript(include_str!("templates/attribute.js"))
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    #[cfg(feature = "sentry")]
    verder_helpen_sentry::SentryLogger::init();
    let mut base = rocket::build()
        .manage(channel::<AttributesUpdateEvent>(1024).0)
        .mount("/internal", routes![auth_result, clean_db,])
        .mount("/guest", routes![init, start,])
        .mount(
            "/host",
            routes![session_info, attribute_ui, attribute_css, attribute_js,],
        )
        .attach(SessionDBConn::fairing());

    let config = base.figment().extract::<Config>().unwrap_or_else(|_| {
        // Drop error value, as it could contain secrets
        panic!("Failure to parse configuration")
    });

    // attach Auth provider fairing
    if let Some(auth_provider) = config.auth_provider() {
        base = base.attach(auth_provider.fairing());
    }

    #[cfg(feature = "sentry")]
    if let Some(dsn) = config.sentry_dsn() {
        base = base.attach(verder_helpen_sentry::SentryFairing::new(
            dsn,
            "comm-isolate",
        ));
    }

    let base = base
        .manage(config)
        .ignite()
        .await
        .expect("Failed to ignite");

    let connection = SessionDBConn::get_one(&base)
        .await
        .expect("Failed to fetch database connection for periodic cleanup");
    rocket::tokio::spawn(async move {
        session::periodic_cleanup(&connection, None)
            .await
            .expect("Failed cleanup");
    });

    base.launch().await?;
    Ok(())
}
