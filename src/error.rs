use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to generate key: {0}")]
    KeyGenerationError(#[from] openssl::error::ErrorStack),
    #[error("Failed to decode base64: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Failed to decompress deflate: {0}")]
    DeflateDecodeError(#[from] std::io::Error),
    #[error("Failed to render template: {0}")]
    TemplateError(#[from] askama::Error),
    #[error("Failed to parse the XML document: {0}")]
    XmlError(#[from] roxmltree::Error),
    #[error("Expected AuthnRequest")]
    ExpectedAuthnRequestError,
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Invalid name ID {0}")]
    InvalidNameID(String)
}
