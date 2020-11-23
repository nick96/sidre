use serde::{ser::Serializer, Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use warp::{http::Response, Rejection, Reply};

#[derive(Deserialize, Debug, Clone)]
struct NameIdFormat(samael::metadata::NameIdFormat);

impl Serialize for NameIdFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.value())
    }
}

impl Default for NameIdFormat {
    fn default() -> Self {
        NameIdFormat(samael::metadata::NameIdFormat::EmailAddressNameIDFormat)
    }
}

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

#[tracing::instrument(level = "info", skip(config))]
pub async fn idp_config_handler(
    id: String,
    db: PgPool,
    config: IdentityProviderConfig,
) -> Result<impl Reply, Rejection> {
    tracing::debug!("Received IdP config: {:?}", config.clone());
    Ok(Response::builder().status(501).body(""))
}

#[tracing::instrument(level = "info")]
pub async fn idp_sp_config_handler(idp_id: String, sp_id: String) -> Result<impl Reply, Rejection> {
    Ok(Response::builder().status(501).body(""))
}

#[cfg(test)]
mod test {
    #[test]
    fn test_update_idp_config() {
        // TODO-test: Write a test that checks the IdP config is updated.
    }

    #[test]
    fn test_update_sp_idp_config() {
        // TODO-test: Write a test that check the SP config is updated.
    }
}
