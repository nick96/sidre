use std::io::Read;

use askama::Template;
use flate2::read::DeflateDecoder;
use rand::Rng;
use samael::{
    idp::{
        response_builder::ResponseAttribute, sp_extractor::RequiredAttribute,
        verified_request::UnverifiedAuthnRequest, IdentityProvider,
    },
    metadata::NameIdFormat,
};
use serde::Deserialize;
use warp::{http, Rejection, Reply};

use crate::{
    error::Error,
    identity_provider::IdP,
    service_provider::ServiceProvider,
    store::{self, Store},
};

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
        },
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

#[tracing::instrument(
    level = "info",
    skip(store, saml_request, relay_state, entity_id)
)]
async fn run_login<S: Store>(
    entity_id: String,
    saml_request: String,
    relay_state: Option<String>,
    store: S,
) -> Result<String, Error> {
    tracing::debug!("Running login for IdP {}", entity_id);
    tracing::debug!("Relay state: {:?}", relay_state);
    tracing::debug!("Encoded SAML request: {}", saml_request);

    let buf = deflate_request(saml_request)?;
    tracing::debug!("Inflated SAML request: {}", buf);

    let unverified_request = UnverifiedAuthnRequest::from_xml(&buf)?;
    let issuer = dig_issuer(&unverified_request)?;
    // Clone the ID here so we can use it when getting the SP as well.
    let idp_entity_id = entity_id.clone();
    let idp: IdP = store.get_identity_provider(&entity_id).await.map_err(
        move |e: crate::store::Error| match e {
            crate::store::Error::NotFound(_) => {
                tracing::info!("No identity provider with ID {}", entity_id);
                Error::IdentityProviderNotFound(entity_id)
            },
            e => {
                tracing::error!(
                    "Failed to get IdP {} from the database: {}",
                    entity_id,
                    e
                );
                e.into()
            },
        },
    )?;
    tracing::debug!("Retrieved IdP by entity ID {}: {:?}", idp_entity_id, idp);

    let sp: ServiceProvider = store
        .get_service_provider(&issuer)
        .await
        .map_err(|e: store::Error| match e {
            // We want to differentiate between no SP with the given ID not
            // existing and other errors. Because not existing is a 404
            // but other errors are 5xx.
            store::Error::NotFound(_) => {
                tracing::info!(
                    "No service provider with entity ID {} for IdP {} found",
                    issuer,
                    idp_entity_id
                );
                Error::ServiceProviderNotFound(
                    idp_entity_id,
                    issuer.to_string(),
                )
            },
            e => {
                tracing::error!(
                    "Failed to get service provider {} for IdP {} from the \
                     store: {}",
                    issuer,
                    idp_entity_id,
                    e
                );
                e.into()
            },
        })?;
    tracing::debug!("Retrieved SP by entity ID {}: {:?}", issuer, sp);
    // TODO-correctness: Get all the keys associated with the SP and try them
    // all. let sp_key = sqlx::query!("SELECT * FROM sp_keys WHERE sp_id =
    // $1", sp.id)     .fetch_one(db)
    //     .await?;
    // TODO-config: Allow configuring whether or not the request should be
    // signed. let verified_request =
    // unverified_request.try_verify_with_cert(&sp_key.key)?;
    let identity_provider =
        IdentityProvider::from_private_key_der(&idp.private_key)?;
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
    let login_form = LoginForm {
        sp_consume_endpoint: sp.consume_endpoint,
        saml_response: base64::encode(response_xml),
        relay_state,
    }
    .render()?;
    Ok(login_form)
}

/// Handle login.
///
/// This is the handler of the endpoint that service providers will redirect
/// users to on login. As `sidre` is intended for use in testing, there is no
/// actual authentication, the user is just redirect back to the service
/// provider with a SAML assertion.
///
/// The redirection is done via a form (templated from
/// [templates/form.html](templates/form.html)) which submits a form containing
/// the SAML response and the  relay state (optional) to the service provider's
/// assertion consumer service (usually just a specific) endpoint of the app.
#[tracing::instrument(level = "info", skip(store, query))]
pub async fn login_handler<S: Store>(
    entity_id: String,
    query: LoginRequestParams,
    store: S,
) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", entity_id);
    tracing::debug!("Query params: {:?}", query);
    match run_login(entity_id, query.saml_request, query.relay_state, store)
        .await
    {
        Ok(form) => Ok(http::Response::builder()
            .status(200)
            .header(warp::http::header::CONTENT_TYPE, "text/html")
            .body(form)),
        Err(e @ Error::IdentityProviderNotFound(_)) => {
            tracing::info!("Identity provider not found: {:?}", e);
            Ok(http::Response::builder().status(404).body("".into()))
        },
        Err(e @ Error::ServiceProviderNotFound(_, _)) => {
            tracing::info!("Service provider not found: {:?}", e);
            Ok(http::Response::builder().status(404).body("".into()))
        },
        Err(e) => {
            tracing::error!("Failed to perform login: {:?}", e);
            Ok(http::Response::builder().status(500).body("".into()))
        },
    }
}

#[cfg(test)]
mod test {
    use std::io::prelude::Write;

    use flate2::{write::DeflateEncoder, Compression};
    use rand::Rng;
    use samael::{
        crypto::decode_x509_cert,
        metadata::{EntityDescriptor, NameIdFormat},
    };
    use sha2::Digest;

    use super::run_login;
    use crate::{
        app,
        identity_provider::ensure_idp,
        service_provider::create_service_provider,
        store::{get_store_for_test, Store},
        try_init_tracing,
    };

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    fn prepare_request_for_url(request: String) -> String {
        let mut encoder =
            DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(request.as_bytes()).unwrap();
        let deflated_request = encoder
            .finish()
            .expect("failed to finalise deflate encoder");
        base64::encode(deflated_request)
    }

    async fn run_login_with_test_data<S: Store>(
        store: S,
        idp_entity_id: &str,
        relay_state: Option<String>,
    ) -> String {
        let request_xml = include_bytes!("../test-data/saml_request.xml");
        let encoded_request = prepare_request_for_url(
            std::str::from_utf8(request_xml)
                .expect("Failed to convert saml_request.xml contents to UTF-8")
                .to_string(),
        );
        run_login(
            idp_entity_id.to_string(),
            encoded_request,
            relay_state,
            store,
        )
        .await
        .expect("Failed to run login")
    }

    // https://github.com/onelogin/ruby-saml/blob/24e90a3ec658d3ced0af7bfcdce1ce656830d9f6/lib/xml_security.rb#L223-L229
    #[tokio::test]
    async fn test_idp_cert_fingerprint_in_response() {
        try_init_tracing();

        let idp_entity_id = random_string();
        let sp_entity_id = "http://sp.example.com/demo1/metadata.php";
        let host = random_string();
        let consume_endpoint = random_string();
        let certificates = vec![];

        let store = get_store_for_test();
        let idp = ensure_idp(store.clone(), &idp_entity_id, &host)
            .await
            .unwrap();

        create_service_provider(
            store.clone(),
            &idp_entity_id,
            sp_entity_id,
            NameIdFormat::EmailAddressNameIDFormat.value(),
            &consume_endpoint,
            certificates,
        )
        .await
        .unwrap();

        let raw_response =
            run_login_with_test_data(store, &idp_entity_id, None).await;
        let response = roxmltree::Document::parse(&raw_response)
            .expect("Failed to parse response");
        let base64_saml_response = response
            .descendants()
            .find_map(|elem| {
                if elem.has_tag_name("input")
                    && elem.attribute("name") == Some("SAMLResponse")
                {
                    elem.attribute("value")
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "Failed to find SAMLResponse attribute on input element \
                     of {}",
                    raw_response
                )
            });
        let saml_response = base64::decode(base64_saml_response)
            .expect("SAMLResponse is invalid base64");
        let parsed_saml_response = roxmltree::Document::parse(
            std::str::from_utf8(&saml_response)
                .expect("decoded SAMLResponse is invalid utf-8"),
        )
        .expect("failed to parse SAMLResponse");
        let encoded_cert = parsed_saml_response
            .descendants()
            .find_map(|node| {
                if node.has_tag_name("X509Certificate") {
                    node.text()
                } else {
                    None
                }
            })
            .expect("failed to find X509Certificate in SAML response");
        let der_cert =
            decode_x509_cert(encoded_cert).expect("Failed to decode cert cert");
        let fingerprint = sha2::Sha256::digest(&der_cert);

        let idp_cert = idp.certificate;
        let expected_fingerprint = sha2::Sha256::digest(&idp_cert);

        assert_eq!(fingerprint, expected_fingerprint);
    }

    #[tokio::test]
    async fn test_returns_relay_state() {
        let idp_entity_id = random_string();
        let sp_entity_id = "http://sp.example.com/demo1/metadata.php";
        let host = random_string();
        let consume_endpoint = random_string();
        let certificates = vec![];

        let store = get_store_for_test();
        let _ = ensure_idp(store.clone(), &idp_entity_id, &host)
            .await
            .unwrap();
        create_service_provider(
            store.clone(),
            &idp_entity_id,
            sp_entity_id,
            NameIdFormat::EmailAddressNameIDFormat.value(),
            &consume_endpoint,
            certificates,
        )
        .await
        .unwrap();
        let expected_relay_state = random_string();

        let raw_response = run_login_with_test_data(
            store,
            &idp_entity_id,
            Some(expected_relay_state.clone()),
        )
        .await;
        let response = roxmltree::Document::parse(&raw_response)
            .expect("Failed to parse response");

        let relay_state = response
            .descendants()
            .find_map(|node| {
                if node.has_tag_name("input")
                    && node.attribute("name") == Some("RelayState")
                {
                    node.attribute("value")
                } else {
                    None
                }
            })
            .expect("Failed to find RelayState in response");

        assert_eq!(relay_state, expected_relay_state);
    }

    #[tokio::test]
    async fn test_cert_in_metadata_same_as_cert_in_response() {
        let store = get_store_for_test();
        let idp_entity_id = random_string();
        let sp_entity_id = "http://sp.example.com/demo1/metadata.php";
        let consume_endpoint = random_string();
        let certificates = vec![];

        let filter = app(store.clone()).await;
        let metadata_response = warp::test::request()
            .header("Host", "http://localhost:8080")
            .path(&format!("/{}/metadata", idp_entity_id))
            .reply(&filter)
            .await;
        assert_eq!(metadata_response.status(), 200);
        let metadata_xml = std::str::from_utf8(metadata_response.body())
            .expect("failed to convert metadata response to utf8 string");
        let metadata: EntityDescriptor = metadata_xml
            .parse()
            .expect("failed to parse metadata response into EntityDescriptor");
        let metadata_cert_base64 = metadata
            .idp_sso_descriptors
            .clone()
            .expect("idp_sso_descriptors")
            .first()
            .expect("idp_sso_descriptors[0]")
            .key_descriptors
            .clone()
            .first()
            .expect("key_descriptors[0]")
            .key_info
            .x509_data
            .clone()
            .expect("x509_data")
            .certificate
            .expect("certificate");
        let metadata_cert = base64::decode(metadata_cert_base64)
            .expect("failed to decode base64 encoded cert in metadata");
        create_service_provider(
            store.clone(),
            &idp_entity_id,
            sp_entity_id,
            NameIdFormat::EmailAddressNameIDFormat.value(),
            &consume_endpoint,
            certificates,
        )
        .await
        .unwrap();

        let raw_response =
            run_login_with_test_data(store, &idp_entity_id, None).await;
        let response = roxmltree::Document::parse(&raw_response)
            .expect("Failed to parse response");
        let encoded_saml_response = response
            .descendants()
            .find_map(|elem| {
                if elem.has_tag_name("input")
                    && elem.attribute("name") == Some("SAMLResponse")
                {
                    elem.attribute("value")
                } else {
                    None
                }
            })
            .expect("Failed to find SAMLResponse attribute on input element");
        let saml_response = base64::decode(encoded_saml_response)
            .expect("failed to decode SAMLResponse");
        let parsed_saml_response = roxmltree::Document::parse(
            std::str::from_utf8(&saml_response)
                .expect("SAMLResponse is invalid utf-8"),
        )
        .expect("failed to parse SAMLResponse");
        let encoded_cert = parsed_saml_response
            .descendants()
            .find_map(|node| {
                if node.has_tag_name("X509Certificate") {
                    node.text()
                } else {
                    None
                }
            })
            .expect("failed to find X509Certificate in SAML response");
        let der_cert =
            decode_x509_cert(encoded_cert).expect("Failed to decode cert cert");

        assert_eq!(metadata_cert, der_cert);
    }
}
