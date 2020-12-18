use crate::{
    error::Error,
    identity_provider::IdP,
    service_provider::ServiceProvider,
    store::{self, Store},
};
use askama::Template;
use flate2::read::DeflateDecoder;
use rand::Rng;
use samael::{
    idp::response_builder::ResponseAttribute,
    idp::sp_extractor::RequiredAttribute,
    idp::{verified_request::UnverifiedAuthnRequest, IdentityProvider},
    metadata::NameIdFormat,
};
use serde::Deserialize;
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

#[tracing::instrument(level = "info", skip(request))]
fn deflate_request(request: String) -> Result<String, Error> {
    let deflated_request = base64::decode(request)?;
    let mut deflater = DeflateDecoder::new(&deflated_request[..]);
    let mut buf = String::new();
    deflater.read_to_string(&mut buf)?;
    Ok(buf)
}

fn dig_issuer(request: &UnverifiedAuthnRequest) -> Result<String, Error> {
    request
        .request
        .clone()
        .issuer
        .ok_or(Error::MissingAuthnRequestIssuer)?
        .value
        .ok_or(Error::MissingAuthnRequestIssuer)
}

#[tracing::instrument(level = "info", skip(store, saml_request, relay_state, id))]
async fn run_login<S: Store>(
    id: String,
    saml_request: String,
    relay_state: Option<String>,
    store: S,
) -> Result<String, Error> {
    tracing::debug!("Running login for IdP {}", id);
    tracing::debug!("Relay state: {:?}", relay_state);
    tracing::debug!("Encoded SAML request: {}", saml_request);

    let buf = deflate_request(saml_request)?;
    tracing::debug!("Inflated SAML request: {}", buf);

    let unverified_request = UnverifiedAuthnRequest::from_xml(&buf)?;
    let issuer = dig_issuer(&unverified_request)?;
    // Clone the ID here so we can use it when getting the SP as well.
    let idp_id = id.clone();
    let idp: IdP =
        store
            .get_identity_provider(id)
            .await
            .map_err(move |e: crate::store::Error| match e {
                crate::store::Error::NotFound(_) => {
                    tracing::info!("No identity provider with ID {}", id);
                    Error::IdentityProviderNotFound(id)
                }
                e => {
                    tracing::error!("Failed to get IdP {} from the database: {}", id, e);
                    e.into()
                }
            })?;

    let sp: ServiceProvider =
        store
            .get_service_provider(&id)
            .await
            .map_err(|e: store::Error| match e {
                // We want to differentiate between no SP with the given ID not existing and other errors. Because not existing is a 404
                // but other errors are 5xx.
                store::Error::NotFound(_) => {
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
    // let sp_key = sqlx::query!("SELECT * FROM sp_keys WHERE sp_id = $1", sp.id)
    //     .fetch_one(db)
    //     .await?;
    // TODO-config: Allow configuring whether or not the request should be signed.
    // let verified_request = unverified_request.try_verify_with_cert(&sp_key.key)?;
    let identity_provider = IdentityProvider::from_private_key_der(&idp.private_key)?;
    let (first_name, last_name, email) = crate::generation::basic_attributes();
    let response = identity_provider.sign_authn_response(
        &idp.certificate,
        // TODO-config: Allow more control over who the assertion is for.
        // TODO-config: Handle more than just email address for name ID format.
        &random_name_id(NameIdFormat::EmailAddressNameIDFormat),
        // TODO-correctness: What should this be? Is the SP's entity ID correct.
        &sp.entity_id,
        &sp.consume_endpoint,
        &idp.entity_id,
        &unverified_request.request.id,
        // TODO-config: Allow specifying the attributes to return.
        &[
            ResponseAttribute {
                required_attribute: RequiredAttribute {
                    name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
                        .to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string()),
                },
                value: &first_name,
            },
            ResponseAttribute {
                required_attribute: RequiredAttribute {
                    name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
                        .to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string()),
                },
                value: &last_name,
            },
            ResponseAttribute {
                required_attribute: RequiredAttribute {
                    name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                        .to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string()),
                },
                value: &email,
            },
        ],
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
#[tracing::instrument(level = "info", skip(store, query))]
pub async fn login_handler<S: Store>(
    id: String,
    query: LoginRequestParams,
    store: S,
) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    tracing::debug!("Query params: {:?}", query);
    match run_login(id, query.saml_request, query.relay_state, store).await {
        Ok(form) => Ok(http::Response::builder()
            .status(200)
            .header(warp::http::header::CONTENT_TYPE, "text/html")
            .body(form)),
        Err(e @ Error::IdentityProviderNotFound(_)) => {
            tracing::info!("Identity provider not found: {:?}", e);
            Ok(http::Response::builder().status(404).body("".into()))
        }
        Err(e @ Error::ServiceProviderNotFound(_, _)) => {
            tracing::info!("Service provider not found: {:?}", e);
            Ok(http::Response::builder().status(404).body("".into()))
        }
        Err(e) => {
            tracing::error!("Failed to perform login: {:?}", e);
            Ok(http::Response::builder().status(500).body("".into()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::run_login;
    use crate::app;
    use crate::db::create_db_pool;
    use crate::identity_provider::ensure_idp;
    use flate2::{write::DeflateEncoder, Compression};
    use rand::Rng;
    use samael::metadata::EntityDescriptor;
    use samael::service_provider::ServiceProvider;
    use sha2::Digest;
    use std::io::prelude::Write;

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    fn prepare_request_for_url(request: String) -> String {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(request.as_bytes()).unwrap();
        let deflated_request = encoder
            .finish()
            .expect("failed to finalise deflate encoder");
        base64::encode(deflated_request)
    }

    async fn run_login_with_test_data(idp_id: &str, relay_state: Option<String>) -> String {
        let request_xml = include_bytes!("../test-data/saml_request.xml");
        let encoded_request = prepare_request_for_url(
            std::str::from_utf8(request_xml)
                .expect("Failed to convert saml_request.xml contents to UTF-8")
                .to_string(),
        );
        let db = create_db_pool().await;
        run_login(idp_id.to_string(), encoded_request, relay_state, &db)
            .await
            .expect("Failed to run login")
    }

    // https://github.com/onelogin/ruby-saml/blob/24e90a3ec658d3ced0af7bfcdce1ce656830d9f6/lib/xml_security.rb#L223-L229
    #[tokio::test]
    async fn test_idp_cert_fingerprint_in_response() {
        let idp_id = random_string();
        let host = random_string();

        let db = create_db_pool().await;
        let idp = ensure_idp(&db, &idp_id, &host).await.unwrap();

        let raw_response = run_login_with_test_data(&idp_id, None).await;
        let response = roxmltree::Document::parse(&raw_response).expect("Failed to parse response");
        let saml_response = response
            .descendants()
            .find_map(|elem| {
                if elem.has_tag_name("input") {
                    let attrs = elem.attributes();
                    if let Some(attr) = attrs.iter().find(|attr| attr.name() == "SAMLResponse") {
                        return Some(attr.value());
                    }
                }
                None
            })
            .expect("Failed to find SAMLResponse attribute on input element");
        let service_provider = ServiceProvider::default();
        let assertion = service_provider
            .parse_response(
                saml_response,
                &["ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"],
            )
            .expect("Failed to parse response");
        let base64_cert = assertion
            .signature
            .expect("signature")
            .key_info
            .expect("key_info")
            .first()
            .expect("key_info[0]")
            .x509_data
            .clone()
            .expect("x509_data")
            .certificate
            .expect("certificate");
        let der_cert = base64::decode(base64_cert).expect("Failed to decode base64 cert");
        let fingerprint = sha2::Sha256::digest(&der_cert);

        let idp_cert = idp.certificate;
        let expected_fingerprint = sha2::Sha256::digest(&idp_cert);

        assert_eq!(fingerprint, expected_fingerprint);
    }

    #[tokio::test]
    async fn test_returns_relay_state() {
        let idp_id = random_string();
        let host = random_string();

        let db = create_db_pool().await;
        let _ = ensure_idp(&db, &idp_id, &host).await.unwrap();
        let expected_relay_state = random_string();

        let raw_response =
            run_login_with_test_data(&idp_id, Some(expected_relay_state.clone())).await;
        let response = roxmltree::Document::parse(&raw_response).expect("Failed to parse response");

        let relay_state = response
            .descendants()
            .find_map(|node| {
                if node.has_tag_name("input") {
                    let attrs = node.attributes();
                    if let Some(attr) = attrs.iter().find(|attr| attr.name() == "RelayState") {
                        return Some(attr.value());
                    }
                }
                None
            })
            .expect("Failed to find RelayState in response");

        assert_eq!(relay_state, expected_relay_state);
    }

    #[tokio::test]
    async fn test_cert_in_metadata_same_as_cert_in_response() {
        let idp_id = random_string();
        let filter = app().await;
        let metadata_response = warp::test::request()
            .header("Host", "http://localhost:8080")
            .path(&format!("/{}/metadata", idp_id))
            .reply(&filter)
            .await;
        assert_eq!(metadata_response.status(), 200);
        let metadata_xml = std::str::from_utf8(metadata_response.body())
            .expect("failed to convert metadata response to utf8 string");
        let metadata: EntityDescriptor = metadata_xml
            .parse()
            .expect("failed to parse metadata response into EntityDescriptor");
        let metadata_cert_base64 = metadata
            .signature
            .clone()
            .expect("signature")
            .key_info
            .expect("key_info")
            .first()
            .expect("key_info[0]")
            .x509_data
            .clone()
            .expect("x509_data")
            .certificate
            .expect("certificate");
        let metadata_cert = base64::decode(metadata_cert_base64)
            .expect("failed to decode base64 encoded cert in metadata");

        let raw_response = run_login_with_test_data(&idp_id, None).await;
        let response = roxmltree::Document::parse(&raw_response).expect("Failed to parse response");
        let saml_response = response
            .descendants()
            .find_map(|elem| {
                if elem.has_tag_name("input") {
                    let attrs = elem.attributes();
                    if let Some(attr) = attrs.iter().find(|attr| attr.name() == "SAMLResponse") {
                        return Some(attr.value());
                    }
                }
                None
            })
            .expect("Failed to find SAMLResponse attribute on input element");
        let service_provider = ServiceProvider::default();
        let assertion = service_provider
            .parse_response(
                saml_response,
                &["ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"],
            )
            .expect("Failed to parse response");
        let base64_cert = assertion
            .signature
            .expect("signature")
            .key_info
            .expect("key_info")
            .first()
            .expect("key_info[0]")
            .x509_data
            .clone()
            .expect("x509_data")
            .certificate
            .expect("certificate");
        let der_cert = base64::decode(base64_cert).expect("Failed to decode base64 cert");

        assert_eq!(metadata_cert, der_cert);
    }
}
