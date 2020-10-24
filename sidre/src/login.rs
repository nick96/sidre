use crate::{error::Error, identity_provider::IdP, service_provider::ServideProviderRow};
use askama::Template;
use flate2::read::DeflateDecoder;
use rand::Rng;
use samael::{
    idp::{verified_request::UnverifiedAuthnRequest, IdentityProvider},
    metadata::NameIdFormat,
};
use serde::Deserialize;
use sqlx::PgPool;
use std::io::Read;
use warp::{http, Rejection, Reply};

#[derive(Template)]
#[template(path = "form.html")]
pub struct LoginForm {
    pub sp_consume_endpoint: String,
    pub saml_response: String,
    pub relay_state: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct LoginRequestParams {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(len)
        .collect()
}

fn random_name_id(format: NameIdFormat) -> String {
    match format {
        NameIdFormat::EmailAddressNameIDFormat => {
            let username = random_string(6);
            let domain = random_string(6);
            format!("{}@{}.local", username, domain)
        }
        _ => unimplemented!(
            "Random generation of name ID format {} is not implemeneted",
            format.value()
        ),
    }
}

#[tracing::instrument(level = "info", skip(db, saml_request, relay_state, id))]
async fn run_login(
    id: String,
    saml_request: String,
    relay_state: Option<String>,
    db: &PgPool,
) -> Result<String, Error> {
    tracing::debug!("Running login for IdP {}", id);
    tracing::debug!("Relay state: {:?}", relay_state);
    tracing::debug!("Encoded SAML request: {}", saml_request);

    let deflated_request = base64::decode(saml_request)?;
    let mut deflater = DeflateDecoder::new(&deflated_request[..]);
    let mut buf = String::new();
    deflater.read_to_string(&mut buf)?;

    tracing::debug!("Inflated SAML request: {}", buf);

    let unverified_request = UnverifiedAuthnRequest::from_xml(&buf)?;
    let unverified_authn_request = unverified_request.request.clone();
    let issuer = unverified_authn_request
        .issuer
        .ok_or_else(|| Error::MissingAuthnRequestIssuer)?
        .value
        .ok_or_else(|| Error::MissingAuthnRequestIssuer)?;
    // Clone the ID here so we can use it when getting the SP as well.
    let idp_id = id.clone();
    let idp: IdP = sqlx::query_as!(
        IdP,
        "
        SELECT id
            , private_key
            , entity_id
            , metadata_valid_until
            , certificate
            , name_id_format
            , redirect_url 
            FROM idps WHERE id = $1",
        id
    )
    .fetch_one(db)
    .await
    .map_err(move |e: sqlx::Error| match e {
        sqlx::Error::RowNotFound => {
            tracing::info!("No identity provider with ID {}", id);
            Error::IdentityProviderNotFound(id)
        }
        e => {
            tracing::error!("Failed to get IdP {} from the database: {}", id, e);
            e.into()
        }
    })?;

    let sp: ServideProviderRow = sqlx::query_as("SELECT * FROM sps WHERE entity_id = $1")
        .bind(issuer.clone())
        .fetch_one(db)
        .await
        .map_err(|e: sqlx::Error| match e {
            // We want to differentiate between no SP with the given ID not existing and other errors. Because not existing is a 404
            // but other errors are 5xx.
            sqlx::Error::RowNotFound => {
                tracing::info!(
                    "No service provider with entity ID {} for IdP {} found",
                    issuer,
                    idp_id
                );
                Error::ServiceProviderNotFound(idp_id, issuer.to_string())
            }
            e => {
                tracing::error!(
                    "Failed to get service provider {} for IdP {} from the database: {}",
                    issuer,
                    idp_id,
                    e
                );
                e.into()
            }
        })?;
    // TODO-correctness: Get all the keys associated with the SP and try them all.
    let sp_key = sqlx::query!("SELECT * FROM sp_keys WHERE sp_id = $1", sp.id)
        .fetch_one(db)
        .await?;
    let verified_request = unverified_request.try_verify_with_cert(&sp_key.key)?;
    let identity_provider = IdentityProvider::from_private_key_der(&idp.private_key)?;
    let response = identity_provider.sign_authn_response(
        &idp.certificate,
        // TODO-config: Allow more control over who the assertion is for.
        // TODO-config: Handle more than just email address for name ID format.
        &random_name_id(NameIdFormat::EmailAddressNameIDFormat),
        // TODO-correctness: What should this be? Is the SP's entity ID correct.
        &sp.entity_id,
        &sp.consume_endpoint,
        &idp.entity_id,
        &verified_request.id,
        // TODO-config: Allow specifying the attributes to return.
        &[],
    )?;
    let response_xml = response.to_xml()?;
    tracing::debug!("SAML assertion: {}", response_xml);
    Ok(LoginForm {
        sp_consume_endpoint: sp.consume_endpoint,
        saml_response: base64::encode(response_xml),
        relay_state,
    }
    .render()?)
}

/// Handle login.
///
/// This is the handler of the endpoint that service providers will redirect
/// users to on login. As `sidre` is intended for use in testing, there is no
/// actual authentication, the user is just redirect back to the service provider
/// with a SAML assertion.
///
/// The redirection is done via a form (templated from [templates/form.html](templates/form.html))
/// which submits a form containing the SAML response and the  relay state (optional)
/// to the service provider's assertion consumer service (usually just a specific)
/// endpoint of the app.
#[tracing::instrument(level = "info", skip(db, query))]
pub async fn login_handler(
    id: String,
    query: LoginRequestParams,
    db: PgPool,
) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    tracing::debug!("Query params: {:?}", query);
    match run_login(id, query.saml_request, query.relay_state, &db).await {
        Ok(form) => Ok(http::Response::builder()
            .status(200)
            .header(warp::http::header::CONTENT_TYPE, "text/html")
            .body(form)),
        Err(e) => {
            tracing::error!("Failed to perform login: {}", e);
            Ok(http::Response::builder().status(500).body("".into()))
        }
    }
}
