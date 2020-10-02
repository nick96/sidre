use crate::{error::Error, templates::LoginForm};
use askama::Template;
use flate2::read::DeflateDecoder;
use roxmltree::Document;
use serde::Deserialize;
use std::io::Read;
use warp::{http::Response, Rejection, Reply};
#[derive(Deserialize)]
pub struct LoginRequestParams {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

async fn run_login(
    id: String,
    saml_request: String,
    relay_state: Option<String>,
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

    Ok(LoginForm {
        sp_consume_endpoint: "".into(),
        saml_response: "".into(),
        relay_state: relay_state,
    }
    .render()?)
}

pub async fn login_handler(id: String, query: LoginRequestParams) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    match run_login(id, query.saml_request, query.relay_state).await {
        Ok(form) => Ok(Response::builder()
            .status(200)
            .header(warp::http::header::CONTENT_TYPE, "text/html")
            .body(form)),
        Err(e) => {
            tracing::error!("Failed to perform login: {}", e);
            Ok(Response::builder().status(500).body("".into()))
        }
    }
}
