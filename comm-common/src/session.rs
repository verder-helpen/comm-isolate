use std::time::Duration;

use crate::{error::Error, types::GuestToken};
use rocket::tokio;
use rocket_sync_db_pools::{database, postgres};
use serde::{Deserialize, Serialize};

#[database("session")]
pub struct SessionDBConn(postgres::Client);

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Session {
    /// The guest token associated with this session
    pub guest_token: GuestToken,
    /// The autheniction result. `None` if none was received yet
    pub auth_result: Option<String>,
    /// ID used to match incoming attributes with this session
    pub attr_id: String,
}

impl Session {
    /// Create a new session
    pub fn new(guest_token: GuestToken, attr_id: String) -> Self {
        Self {
            attr_id,
            guest_token,
            auth_result: None,
        }
    }

    /// Persist a sessions. This can only be done for newly created sessions,
    /// as the session id is unique.
    pub async fn persist(&self, db: &SessionDBConn) -> Result<(), Error> {
        let this = self.clone();
        let res = db
            .run(move |c| {
                c.execute(
                    "INSERT INTO session (
                session_id,
                room_id,
                redirect_url,
                purpose,
                name,
                attr_id,
                auth_result,
                last_activity
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, now());",
                    &[
                        &this.guest_token.id,
                        &this.guest_token.room_id,
                        &this.guest_token.redirect_url,
                        &this.guest_token.purpose,
                        &this.guest_token.name,
                        &this.attr_id,
                        &this.auth_result,
                    ],
                )
            })
            .await;

        res.map_err(|e| {
            if let Some(&postgres::error::SqlState::UNIQUE_VIOLATION) = e.code() {
                Error::BadRequest("A session with that ID already exists")
            } else {
                Error::from(e)
            }
        })?;
        Ok(())
    }

    /// Mark a session as active
    pub async fn mark_active(&self, db: &SessionDBConn) -> Result<(), Error> {
        let this = self.clone();
        match db
            .run(move |c| {
                c.execute(
                    "UPDATE session
                SET last_activity = now()
                WHERE session_id = $1",
                    &[&this.guest_token.id],
                )
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Restart authentication for a guest token if it already exists.
    /// if not, this function returns false.
    pub async fn restart_auth(
        token: GuestToken,
        new_attr_id: String,
        db: &SessionDBConn,
    ) -> Result<bool, Error> {
        let n = db
            .run(move |c| {
                c.execute(
                    "UPDATE session SET attr_id=$1 WHERE
                session_id = $2 AND
                room_id = $3 AND
                redirect_url = $4 AND
                purpose = $5 AND
                name = $6 AND
                auth_result IS NULL",
                    &[
                        &new_attr_id,
                        &token.id,
                        &token.room_id,
                        &token.redirect_url,
                        &token.purpose,
                        &token.name,
                    ],
                )
            })
            .await?;

        Ok(n == 1)
    }

    /// Register an authentication result with a session. Fails if the session
    /// already contains an authentication result.
    pub async fn register_auth_result(
        attr_id: String,
        auth_result: String,
        db: &SessionDBConn,
    ) -> Result<(), Error> {
        let n = db
            .run(move |c| {
                c.execute(
                    "UPDATE session
                    SET (auth_result, last_activity) = ($1, now())
                    WHERE auth_result IS NULL
                    AND attr_id = $2;",
                    &[&auth_result, &attr_id],
                )
            })
            .await?;

        match n {
            1 => Ok(()),
            _ => Err(Error::NotFound),
        }
    }

    /// Find sessions by room ID
    pub async fn find_by_room_id(room_id: String, db: &SessionDBConn) -> Result<Vec<Self>, Error> {
        let sessions = db
            .run(move |c| -> Result<Vec<Session>, Error> {
                let rows = c.query(
                    "
                    UPDATE session
                    SET last_activity = now()
                    WHERE room_id = $1
                    RETURNING
                        session_id,
                        room_id,
                        redirect_url,
                        purpose,
                        name,
                        attr_id,
                        auth_result
                    ",
                    &[&room_id],
                )?;
                if rows.is_empty() {
                    return Err(Error::NotFound);
                }
                rows.into_iter()
                    .map(|r| -> Result<_, Error> {
                        let guest_token = GuestToken {
                            id: r.get("session_id"),
                            room_id: r.get("room_id"),
                            redirect_url: r.get("redirect_url"),
                            name: r.get("name"),
                            purpose: r.get("purpose"),
                        };
                        Ok(Session {
                            guest_token,
                            attr_id: r.get("attr_id"),
                            auth_result: r.get("auth_result"),
                        })
                    })
                    .collect()
            })
            .await?;

        Ok(sessions)
    }
}

/// Remove all sessions that have been inactive for an hour or more
pub async fn clean_db(db: &SessionDBConn) -> Result<(), Error> {
    db.run(move |c| {
        c.execute(
            "DELETE FROM session WHERE last_activity < now() - INTERVAL '1 hour'",
            &[],
        )
    })
    .await?;
    Ok(())
}

pub async fn periodic_cleanup(db: &SessionDBConn, period: Option<u64>) -> Result<(), Error> {
    let duration = Duration::from_secs(period.unwrap_or(5) * 60);
    let mut interval = tokio::time::interval(duration);

    loop {
        interval.tick().await;
        clean_db(db).await?;
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Format, Toml},
        Figment,
    };
    use serial_test::serial;

    use crate::{
        prelude::{random_string, GuestToken, SessionDBConn},
        session::clean_db,
    };

    use super::Session;

    async fn init_db() -> Option<SessionDBConn> {
        if let Some(test_db) = option_env!("TEST_DB") {
            // Easiest (perhaps only) way to get a SessionDBConn is to actually get us a rocket instance that has ignited.
            // this is to deal with all the rewrites rocket does on that struct.
            let figment = Figment::from(rocket::Config::default())
                .select(rocket::Config::DEBUG_PROFILE)
                .merge(
                    Toml::string(&format!(
                        r#"
[global.databases]
session = {{ url = "{}" }}
"#,
                        test_db
                    ))
                    .nested(),
                );
            let rocket = rocket::custom(figment)
                .attach(SessionDBConn::fairing())
                .ignite()
                .await
                .unwrap();
            let db_session = SessionDBConn::get_one(&rocket).await.unwrap();
            db_session
                .run(|c| {
                    c.batch_execute(include_str!("../schema.sql")).unwrap();
                    println!("Database prepared");
                })
                .await;
            Some(db_session)
        } else {
            None
        }
    }

    fn bogus_session(id: Option<String>, room_id: Option<String>) -> Session {
        let guest_token = GuestToken {
            purpose: "test".to_owned(),
            id: id.unwrap_or_else(|| random_string(32)),
            redirect_url: "verderhelpen.nl".to_owned(),
            name: "Test Verder Helpen".to_owned(),
            room_id: room_id.unwrap_or_else(|| random_string(32)),
        };

        Session {
            guest_token,
            auth_result: None,
            attr_id: random_string(32),
        }
    }

    async fn insert_session_with_age(s: Session, db: &SessionDBConn, age: String) {
        db.run(move |c| {
            let query = format!(
                "INSERT INTO session (
                session_id,
                room_id,
                redirect_url,
                purpose,
                name,
                attr_id,
                auth_result,
                last_activity
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, now() - INTERVAL '{}');",
                age
            );

            c.execute(
                query.as_str(),
                &[
                    &s.guest_token.id,
                    &s.guest_token.room_id,
                    &s.guest_token.redirect_url,
                    &s.guest_token.purpose,
                    &s.guest_token.name,
                    &s.attr_id,
                    &s.auth_result,
                ],
            )
        })
        .await
        .unwrap();
    }

    #[test]
    // this ensures test is not parallelised with other serial tests, ensuring only one database test is run at a time.
    #[serial]
    fn test_register_auth_result() {
        tokio_test::block_on(async {
            if let Some(db) = init_db().await {
                let s = bogus_session(None, None);
                s.persist(&db).await.unwrap();

                Session::register_auth_result(
                    s.attr_id.to_owned(),
                    "invalid_auth_result".to_owned(),
                    &db,
                )
                .await
                .unwrap();

                let sessions = Session::find_by_room_id(s.guest_token.room_id.to_owned(), &db)
                    .await
                    .unwrap();

                assert_eq!(sessions.len(), 1);
                assert_eq!(
                    sessions[0].auth_result,
                    Some("invalid_auth_result".to_owned())
                )
            }
        });
    }

    #[test]
    #[serial]
    fn test_clean_db() {
        tokio_test::block_on(async {
            if let Some(db) = init_db().await {
                let room_id = "Room 123 Test".to_owned();

                insert_session_with_age(
                    bogus_session(None, Some(room_id.clone())),
                    &db,
                    "1 hour".into(),
                )
                .await;
                insert_session_with_age(
                    bogus_session(None, Some(room_id.clone())),
                    &db,
                    "2 hour".into(),
                )
                .await;
                insert_session_with_age(
                    bogus_session(None, Some(room_id.clone())),
                    &db,
                    "1 minute".into(),
                )
                .await;

                clean_db(&db).await.unwrap();

                let sessions = Session::find_by_room_id(room_id, &db).await.unwrap();
                assert_eq!(sessions.len(), 1);
            }
        });
    }
}
