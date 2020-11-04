use crate::error::Error;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use warp::{http::Response, Rejection, Reply};

/// User the IdP can return an assertion for.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    /// Namne ID for the user. This is in the format specified by
    /// [IdentityProviderConifg.name_id_format].
    name_id: String,
    /// Mapping of attributes names to their value. This allows providing custom
    /// information about users. You can use the [ServideProviderConfig.attribute_mapping]
    /// to map these to the attribute types returned in the assertion.
    attributes: HashMap<String, String>,
}

/// Posible name ID formats.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NameIdFormat {
    EmailAddress,
}

impl ToString for NameIdFormat {
    fn to_string(&self) -> String {
        match self {
            Self::EmailAddress => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
            }
        }
    }
}

impl std::str::FromStr for NameIdFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => Ok(Self::EmailAddress),
            _ => Err(Error::InvalidNameIdFormat(s.to_string())),
        }
    }
}

impl Default for NameIdFormat {
    fn default() -> Self {
        Self::EmailAddress
    }
}

/// Configuration for identity providers.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct IdentityProviderConfig {
    /// Whether or not the IdP wants requests to be signed (default: false).
    wants_signed_request: bool,
    /// Format the user's name ID's in [user_store] are stored in.
    name_id_format: NameIdFormat,
    /// Users the IdP can be used to authenticate for.
    user_store: Vec<User>,
}

/// Configuration for service providers.
#[derive(Serialize, Deserialize, Default)]
struct ServideProviderConfig {
    /// Sign the SAML response itself, otherwise just the assertion is signed.
    sign_response: bool,
    /// Mapping of attributes in the IdP's user store
    /// ([IdentityProviderConfig.user_store]) to those understood by the service
    /// provider.
    attribute_mapping: HashMap<String, String>,
}

struct Exists {
    exists: Option<bool>,
}

async fn upsert_idp_config(
    db: &PgPool,
    id: String,
    config: IdentityProviderConfig,
) -> Result<(), Error> {
    match sqlx::query_as!(
        Exists,
        "SELECT EXISTS(SELECT 1 FROM idps WHERE id = $1)",
        id
    )
    .fetch_one(db)
    .await
    {
        Ok(Exists { exists: Some(true) }) => {
            let mut tx = db.begin().await?;

            // Easiest way to upsert is to just delete and recreate
            sqlx::query!(
                "DELETE FROM idp_user_attributes 
                    WHERE user_id IN (SELECT id FROM idp_users WHERE idp_id = $1)",
                id,
            )
            .execute(&mut tx)
            .await?;
            sqlx::query!("DELETE FROM idp_users WHERE idp_id = $1", id)
                .execute(&mut tx)
                .await?;
            sqlx::query!("DELETE FROM idp_config WHERE idp_id = $1", id)
                .execute(&mut tx)
                .await?;

            sqlx::query!(
                "INSERT INTO idp_config(idp_id, wants_signed_request, name_id_format)
                    VALUES($1, $2, $3)",
                id,
                config.wants_signed_request,
                config.name_id_format.to_string(),
            )
            .execute(&mut tx)
            .await?;

            for user in config.user_store {
                let inserted = sqlx::query!(
                    "INSERT INTO idp_users(idp_id, name_id)
                        VALUES($1, $2) RETURNING id",
                    id,
                    user.name_id,
                )
                .fetch_one(&mut tx)
                .await?;

                for (key, value) in user.attributes {
                    sqlx::query!(
                        "INSERT INTO idp_user_attributes(user_id, key, value)
                            VALUES($1, $2, $3)",
                        inserted.id,
                        key,
                        value
                    )
                    .execute(&mut tx)
                    .await?;
                }
            }

            tx.commit().await?;

            Ok(())
        }
        Ok(_) => Err(Error::IdentityProviderNotFound(id)),
        Err(e) => Err(e.into()),
    }
}

#[tracing::instrument(level = "info", skip(config))]
pub async fn idp_config_handler(
    id: String,
    db: PgPool,
    config: IdentityProviderConfig,
) -> Result<impl Reply, Rejection> {
    tracing::debug!("Received IdP config: {:?}", config.clone());
    match upsert_idp_config(&db, id, config.clone()).await {
        Ok(()) => {
            // Just unwrap because there shouldn't be any case where it fails to serialize.
            let json_config = serde_json::to_string(&config).unwrap();
            Ok(Response::builder()
                .status(201)
                .header(warp::http::header::CONTENT_TYPE, "application/json")
                .body(json_config))
        }
        Err(Error::IdentityProviderNotFound(idp_id)) => {
            tracing::info!("No IdP with ID {} found", idp_id);
            Ok(Response::builder().status(404).body("".into()))
        }
        Err(e) => {
            tracing::error!("Failed to upsert IdP config: {}", e);
            Ok(Response::builder().status(500).body("".into()))
        }
    }
}

#[tracing::instrument(level = "info")]
pub async fn idp_sp_config_handler(idp_id: String, sp_id: String) -> Result<impl Reply, Rejection> {
    Ok(warp::reply())
}

#[cfg(test)]
mod test {
    #[test]
    fn test_update_idp_config() {
        todo!()
    }

    #[test]
    fn test_update_sp_idp_config() {
        todo!()
    }
}
