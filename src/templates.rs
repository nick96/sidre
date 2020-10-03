use crate::error::Error;
pub use askama::Template;
use chrono::{DateTime, Utc};
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

#[derive(Clone)]
pub enum NameIDFormat {
    EmailAddress,
}

const EMAIL_ADDRESS_NAME_ID_FMT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

impl std::fmt::Display for NameIDFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NameIDFormat::EmailAddress => write!(f, "{}", EMAIL_ADDRESS_NAME_ID_FMT),
        }
    }
}

impl std::str::FromStr for NameIDFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            EMAIL_ADDRESS_NAME_ID_FMT => Ok(Self::EmailAddress),
            _ => Err(Error::InvalidNameID(s.into())),
        }
    }
}

#[derive(Template)]
#[template(path = "assertion.xml")]
pub struct Assertion {
    pub assertion_id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub name_id_format: NameIDFormat,
    pub name_id: String,
    pub response_id: String,
    pub consume_endpoint: String,
    pub not_on_or_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub sp_entity_id: String,
}

// Convenience trait because we need to build the assertion without the
// signature and stuff to sign it but it's a subset of the response.
impl From<Response> for Assertion {
    fn from(r: Response) -> Self {
        Self {
            assertion_id: r.assertion_id,
            issue_instant: r.issue_instant,
            issuer: r.issuer,
            name_id_format: r.name_id_format,
            name_id: r.name_id,
            response_id: r.response_id,
            consume_endpoint: r.consume_endpoint,
            not_on_or_after: r.not_on_or_after,
            not_before: r.not_before,
            sp_entity_id: r.sp_entity_id,
        }
    }
}

#[derive(Template, Clone)]
#[template(path = "response.xml")]
pub struct Response {
    pub authn_request_id: String,
    pub assertion_id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub name_id_format: NameIDFormat,
    pub name_id: String,
    pub response_id: String,
    pub consume_endpoint: String,
    pub not_on_or_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub sp_entity_id: String,
    pub signature: String,
    pub certificate: String,
}
