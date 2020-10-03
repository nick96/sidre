use crate::{
    error::Error,
    identity_provider::IdP,
    service_provider::SP,
    templates::{Assertion, LoginForm, NameIDFormat, Response},
};
use askama::Template;
use chrono::{Duration, Utc};
use flate2::read::DeflateDecoder;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use rand::Rng;
use roxmltree::Document;
use serde::Deserialize;
use sqlx::PgPool;
use std::io::Read;
use std::str::FromStr;
use warp::{http, Rejection, Reply};

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

fn random_name_id(format: NameIDFormat) -> String {
    match format {
        NameIDFormat::EmailAddress => {
            let username = random_string(6);
            let domain = random_string(6);
            format!("{}@{}.local", username, domain)
        }
    }
}

fn sign_assertion(private_key: Vec<u8>, assertion: Assertion) -> Result<Vec<u8>, Error> {
    let pk = PKey::private_key_from_der(&private_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pk)?;
    let data: String = assertion.render()?;
    signer.update(data.as_bytes())?;
    Ok(signer.sign_to_vec()?)
}

fn generate_saml_response(request_id: String, idp: &IdP, sp: &SP) -> Result<String, Error> {
    let now = Utc::now();
    let name_id_format = NameIDFormat::from_str(&idp.name_id_format)?;
    let mut response = Response {
        authn_request_id: request_id,
        assertion_id: "".into(),
        issue_instant: Utc::now(),
        issuer: idp.entity_id.clone(),
        name_id_format: name_id_format.clone(),
        name_id: random_name_id(name_id_format),
        response_id: "".into(),
        consume_endpoint: sp.consume_endpoint.clone(),
        certificate: base64::encode(idp.certificate.clone()),
        not_before: now,
        not_on_or_after: now + Duration::minutes(5),
        sp_entity_id: sp.entity_id.clone(),
        signature: "".into(),
    };
    let assertion = Assertion::from(response.clone());
    let signature = sign_assertion(idp.private_key.clone(), assertion)?;
    response.signature = base64::encode(signature);
    Ok(response.render()?)
}

#[tracing::instrument(level = "info")]
async fn run_login(
    id: String,
    saml_request: String,
    relay_state: Option<String>,
    db: &PgPool,
) -> Result<String, Error> {
    let deflated_request = base64::decode(saml_request)?;
    let mut deflater = DeflateDecoder::new(&deflated_request[..]);
    let mut buf = String::new();
    deflater.read_to_string(&mut buf)?;

    let doc = Document::parse(&buf)?;
    if !doc.root().has_tag_name("samlp:AuthnRequest") {
        tracing::info!(
            "Expected AuthnRequest document, received {}",
            doc.root().tag_name().name()
        );
        return Err(Error::ExpectedAuthnRequestError);
    }

    // Entity ID of the SP that sent us the request.
    let issuer = doc
        .descendants()
        .find_map(|n| {
            if n.tag_name().name() == "Issuer" {
                n.text()
            } else {
                None
            }
        })
        .ok_or(Error::MissingField("Issuer".into()))?;

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

    let sp: SP = sqlx::query_as("SELECT * FROM sps WHERE entity_id = $1")
        .bind(issuer)
        .fetch_one(db)
        .await
        .map_err(|e: sqlx::Error| match e {
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
    let response = generate_saml_response("".into(), &idp, &sp)?;
    Ok(LoginForm {
        sp_consume_endpoint: sp.consume_endpoint,
        saml_response: base64::encode(response),
        relay_state: relay_state,
    }
    .render()?)
}

#[tracing::instrument(level = "info")]
pub async fn login_handler(
    id: String,
    query: LoginRequestParams,
    db: PgPool,
) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
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
