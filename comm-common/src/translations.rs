use rocket::request::{self, FromRequest, Request};
use rocket::serde::Serialize;
use std::collections::HashMap;
use unic_langid::{parser::parse_language_identifier, LanguageIdentifier};

use crate::config::Config;

#[derive(Serialize, Clone)]
pub struct Translations {
    pub language: String,
    pub translations: HashMap<String, String>,
}

impl<'r> Translations {
    pub fn get(&self, key: &str, fallback: &str) -> String {
        self.translations
            .get(key)
            .unwrap_or(&fallback.to_owned())
            .to_owned()
    }

    pub fn all(&self) -> &HashMap<String, String> {
        &self.translations
    }

    pub fn from_request(req: &'r Request<'_>) -> Translations {
        let config = req
            .rocket()
            .state::<Config>()
            .expect("No configuration found");

        // retrieve the accept langiage header
        let raw_accept_language: Option<&str> = req.headers().get("accept-language").next();

        // parse into normalized language identifiers
        let accept_languages = raw_accept_language
            .map(|raw_accept_language| {
                accept_language::parse(raw_accept_language)
                    .iter()
                    .filter_map(|al| parse_language_identifier(al.as_bytes()).ok())
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        // retrieve translations keys and parse into normalized langiage identifiers
        let keys: Vec<LanguageIdentifier> = config
            .get_language_translations()
            .keys()
            .filter_map(|al| parse_language_identifier(al.as_bytes()).ok())
            .collect();

        // select the first matching language identifier
        let first_lang = accept_languages.iter().find(|l| keys.contains(l));

        // fallback to the configured fallback language
        let lang = match first_lang {
            Some(li) => li.language.as_str(),
            None => &config.default_locale,
        };

        Translations {
            language: lang.to_string(),
            translations: config
                .get_language_translations()
                .get(lang)
                .expect("No translations specified for the default locale")
                .clone(),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Translations {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        request::Outcome::Success(Self::from_request(req))
    }
}
