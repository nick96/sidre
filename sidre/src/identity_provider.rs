use chrono::{DateTime, Duration, Utc};
use samael::{
    idp::{CertificateParams, IdentityProvider, KeyType},
    key_info::{KeyInfo, X509Data},
    metadata::{
        Endpoint, EntityDescriptor, IdpSsoDescriptor, KeyDescriptor,
        NameIdFormat, HTTP_POST_BINDING,
    },
};
use warp::{http::Response, Rejection, Reply};

use crate::{
    error::Error,
    store::{self, Store},
};

// Nothing in particular, 1000 just seems long enough to not be a pain in dev.
const CERT_EXPIRY_IN_DAYS: u32 = 1000;

/// Representation of a row in the `idps` table in the database.
#[derive(Debug)]
pub struct IdP {
    /// Private key used to sign the assertion. In DER format.
    pub private_key: Vec<u8>,
    /// Entity ID for the IdP.
    pub entity_id: String,
    /// Date until the metadata is valid. This is stored when the IdP is first
    /// created by the ensure endpoint and used with subsequent requests to
    /// make the endpoint idempotent.
    pub metadata_valid_until: DateTime<Utc>,
    /// Certificate from the `private_key` so that service providers may verify
    /// assertions.
    pub certificate: Vec<u8>,
    /// Name ID format for the IdP. I'm not sure what the difference between
    /// this and the one requested in the AuthnRequest. I think it may be that
    /// this is used for IdPs to assert which name IDs they can handle then the
    /// servide provider can request the ones they can handle and we shoe the
    /// intersect.
    pub name_id_format: String,
    /// URL to send AuthnRequests to.
    pub redirect_url: String,
}

impl IdP {
    /// Build the [EntityDescriptor] for the [IdP].
    pub fn metadata(&self) -> EntityDescriptor {
        EntityDescriptor {
            entity_id: Some(self.entity_id.clone()),
            valid_until: Some(self.metadata_valid_until),
            idp_sso_descriptors: Some(vec![IdpSsoDescriptor {
                // TODO-config: Allow specifying the name ID formats to
                // advertise.
                name_id_formats: vec![NameIdFormat::EmailAddressNameIDFormat
                    .value()
                    .to_string()],
                single_sign_on_services: vec![Endpoint {
                    // Hard code HTTP-POST binding as that's the most common.
                    // Re-evaluate this if support for the
                    // others is needed in future. See here for the different
                    // types of binding:
                    // https://en.wikipedia.org/wiki/SAML_2.0#SAML_2.0_bindings
                    binding: HTTP_POST_BINDING.to_string(),
                    location: self.redirect_url.clone(),
                    response_location: None,
                }],
                key_descriptors: vec![KeyDescriptor {
                    key_use: Some("signing".to_string()),
                    key_info: KeyInfo {
                        id: None,
                        x509_data: Some(X509Data {
                            certificate: Some(base64::encode(
                                self.certificate.clone(),
                            )),
                        }),
                    },
                    encryption_methods: None,
                }],
                // TODO-config: Allow configuring IdP to want signed request.
                want_authn_requests_signed: Some(false),
                ..IdpSsoDescriptor::default()
            }]),
            ..EntityDescriptor::default()
        }
    }
}

/// Ensure the IdP identified by `id` exists and return it.
///
/// If an IdP with `id` already exists, just get it. Otherwise, construct the
/// required parts (e.g. certificate), insert them in the database, and return
/// the identity provider.
#[tracing::instrument(level = "info", skip(store))]
pub(crate) async fn ensure_idp<S: Store>(
    store: S,
    entity_id: &str,
    host: &str,
) -> Result<IdP, Error> {
    match store.get_identity_provider(entity_id).await {
        Ok(idp) => {
            tracing::info!("IdP {} already exists, just returning", entity_id);
            Ok(idp)
        },
        Err(store::Error::NotFound(_)) => {
            // TODO-config: Allow specifying the key type. Currently Samael only
            // allows RSA keys. Does it make sense to allow Ed25519 as well?
            let idp = IdentityProvider::generate_new(KeyType::Rsa4096)?;

            let certificate_der =
                idp.create_certificate(&CertificateParams {
                    common_name: &format!("{} (sidre)", &entity_id),
                    issuer_name: &entity_id,
                    days_until_expiration: CERT_EXPIRY_IN_DAYS,
                })?;
            let private_key = idp.export_private_key_der()?;
            // TODO-config: Add a knob for the name ID format (email address and
            // persistent ID are probably the most important).
            let name_id_format = NameIdFormat::EmailAddressNameIDFormat.value();
            let redirect_url = format!("http://{}/{}/sso", host, &entity_id);
            let metadata_valid_until =
                Utc::now() + Duration::days(CERT_EXPIRY_IN_DAYS as i64);

            let identity_provider = store
                .create_identity_provider(IdP {
                    private_key,
                    certificate: certificate_der,
                    entity_id: entity_id.into(),
                    metadata_valid_until,
                    name_id_format: name_id_format.to_string(),
                    redirect_url,
                })
                .await?;

            tracing::info!("Created IDP {}", entity_id);

            Ok(identity_provider)
        },
        Err(e) => Err(e.into()),
    }
}

/// Handle getting the IdP's metdata.
///
/// This is the handler for the endpoint that client's GET to retrieve an IdP's
/// metadata. The IdP will be created if it doesn't already exists and the
/// metadata returned. This handler is idempotent in that subsequent requests
/// will return the same metadata.
#[tracing::instrument(level = "info", skip(store))]
pub async fn get_idp_metadata_handler<S: Store>(
    entity_id: String,
    host: String,
    store: S,
) -> Result<impl Reply, Rejection> {
    match ensure_idp(store, &entity_id, &host).await {
        Ok(idp) => match idp.metadata().to_xml() {
            Ok(metadata) => Ok(Response::builder()
                .header(warp::http::header::CONTENT_TYPE, "application/xml")
                .body(metadata)),
            Err(e) => {
                tracing::error!("Failed to convert metadata to XML: {}", e);
                Ok(Response::builder().status(500).body("".to_string()))
            },
        },
        Err(e) => {
            tracing::error!("Failed to ensure IdP: {}", e);
            Ok(Response::builder().status(500).body("".to_string()))
        },
    }
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, Utc};
    use rand::Rng;

    use super::*;
    use crate::store::get_store_for_test;

    #[derive(PartialEq, Debug)]
    struct CreatedAtAndModifiedAt {
        created_at: DateTime<Utc>,
        modified_at: DateTime<Utc>,
    }

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn test_ensure_idp_creates_one_if_it_is_missing() {
        let idp_entity_id = random_string();
        let host = random_string();

        let store = get_store_for_test();
        let _ = ensure_idp(store.clone(), &idp_entity_id, &host)
            .await
            .unwrap();
        let exists = store
            .identity_provider_exists(&idp_entity_id)
            .await
            .unwrap();
        assert!(exists);
    }

    // #[tokio::test]
    // async fn test_ensure_idp_does_not_create_one_if_it_exists() {
    //     let idp_id = random_string();
    //     let host = random_string();

    //     let db = create_db_pool().await;
    //     let _ = ensure_idp(&db, &idp_id, &host).await.unwrap();
    //     let dates = sqlx::query_as!(
    //         CreatedAtAndModifiedAt,
    //         "SELECT created_at, modified_at FROM idps WHERE id = $1",
    //         idp_id
    //     )
    //     .fetch_one(&db)
    //     .await
    //     .unwrap();

    //     let _ = ensure_idp(&db, &idp_id, &host).await.unwrap();
    //     let dates2 = sqlx::query_as!(
    //         CreatedAtAndModifiedAt,
    //         "SELECT created_at, modified_at FROM idps WHERE id = $1",
    //         idp_id
    //     )
    //     .fetch_one(&db)
    //     .await
    //     .unwrap();

    //     assert_eq!(dates, dates2);
    // }
}
