use crate::jwt::JwtError;
use rocket::{
    http::{ContentType, Status},
    Response,
};
use rocket_sync_db_pools::postgres;
use serde_json::json;
use tera;
use thiserror::Error;

#[derive(Debug, Error)]
/// General Error type, used to capture all kinds of common errors. Can be used to respond to requests
pub enum Error {
    #[error("Not found")]
    NotFound,
    #[error("Bad Request: {0}")]
    BadRequest(&'static str),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Internal Server: {0}")]
    InternalServer(String),
    #[error("JWE Error: {0}")]
    Jwe(#[from] JwtError),
    #[error("Postgres Error: {0}")]
    Postgres(#[from] postgres::Error),
    #[error("Reqwest Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("JSON Error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Parse Error: {0}")]
    Parse(#[from] strum::ParseError),
    #[error("Template Error: {0}")]
    Template(#[from] tera::Error),
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        use Error::*;
        let (message, status) = match &self {
            NotFound => ("Not found".to_string(), Status::NotFound),
            BadRequest(m) => (m.to_string(), Status::BadRequest),
            Forbidden(m) => (m.to_string(), Status::Forbidden),
            Unauthorized(m) => (m.to_string(), Status::Unauthorized),
            InternalServer(m) => (m.to_string(), Status::InternalServerError),
            Jwe(m) => (m.to_string(), Status::BadRequest),
            Template(m) => (m.to_string(), Status::InternalServerError),
            _ => return rocket::response::Debug::from(self).respond_to(request),
        };

        // Log the error to stderr
        eprintln!("Error {message}");

        if request.headers().get_one("Accept") == Some("application/json") {
            let body = json!({ "error": status.to_string() });

            return Ok(Response::build_from(body.respond_to(request).unwrap())
                .status(status)
                .header(ContentType::JSON)
                .finalize());
        }

        Ok(
            Response::build_from(status.to_string().respond_to(request).unwrap())
                .status(status)
                .header(ContentType::Text)
                .finalize(),
        )
    }
}

impl From<verder_helpen_jwt::Error> for Error {
    fn from(e: verder_helpen_jwt::Error) -> Self {
        Error::Jwe(JwtError::Jwe(e))
    }
}
