use thiserror::Error;

/// Errors used within the app.
///
/// The names should be pretty self explanatory. It might be worth looking at breaking this down
/// into per app component errors as it's getting pretty large.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to decode base64: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Failed to decompress deflate: {0}")]
    DeflateDecodeError(#[from] std::io::Error),
    #[error("Failed to render template: {0}")]
    TemplateError(#[from] askama::Error),
    #[error("Missing field {0}")]
    MissingField(String),
    #[error("Text is not valid UTF8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("No SP with entity ID {1} found for IdP {0}")]
    ServiceProviderNotFound(String, String),
    #[error("No IdP with ID {0}")]
    IdentityProviderNotFound(String),
    #[error("Samael IdP failure: {0}")]
    SamaelIdPError(#[from] samael::idp::error::Error),
    #[error("No issues found in AuthnRequest")]
    MissingAuthnRequestIssuer,
    #[error("Generic error: {0}")]
    GenericError(#[from] Box<dyn std::error::Error>),
    #[error("Samael SP failure: {0}")]
    SamaelSPError(#[from] samael::service_provider::Error),
    #[error("Samael entity descriptor failure: {0}")]
    SamaelEntityDescriptorError(#[from] samael::metadata::Error),
    #[error("Store failed: {0}")]
    StoreError(#[from] crate::store::Error),
}
