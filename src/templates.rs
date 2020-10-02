pub use askama::Template;
use chrono::{DateTime, Utc};
use crate::error::Error;
/// Template to render the IdP metadata document.
#[derive(Template)]
#[template(path = "metadata.xml")]
pub struct Metadata {
    /// IdP entity ID.
    pub entity_id: String,
    /// Date until which the metadata is valid.
    pub valid_until: DateTime<Utc>,
    /// Base64 x509 certificate user to sign SAML assertions.
    pub certificate: String,
    /// Format name IDs will be returned in.
    pub name_id_format: NameIDFormat,
    /// URL that SP should redirect to.
    pub redirect_url: String,
}

#[derive(Template)]
#[template(path = "form.html")]
pub struct LoginForm {
    pub sp_consume_endpoint: String,
    pub saml_response: String,
    pub relay_state: Option<String>,
}

pub enum NameIDFormat {
    EmailAddress,
}

const EMAIL_ADDRESS_NAME_ID_FMT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

impl std::fmt::Display for NameIDFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NameIDFormat::EmailAddress => {
                write!(f, "{}", EMAIL_ADDRESS_NAME_ID_FMT)
            }
        }
    }
}

impl std::str::FromStr for NameIDFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            EMAIL_ADDRESS_NAME_ID_FMT => Ok(Self::EmailAddress),
            _ => Err(Error::InvalidNameID(s.into()))
        }
    }
}
