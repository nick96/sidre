use snafu::Snafu;

use xmlsec::{self, XmlSecKey, XmlSecKeyFormat, XmlSecSignatureContext};
use libxml::parser::Parser as XmlParser;

#[derive(Debug, Snafu)]
pub enum Error {
    InvalidSignature,

        #[snafu(display("xml sec Error: {}", error))]
    XmlParseError {
        error: libxml::parser::XmlParseError,
    },

        #[snafu(display("xml sec Error: {}", error))]
    XmlSecError {
        error: xmlsec::XmlSecError,
    },
}

impl From<xmlsec::XmlSecError> for Error {
    fn from(error: xmlsec::XmlSecError) -> Self {
        Error::XmlSecError { error }
    }
}

impl From<libxml::parser::XmlParseError> for Error {
    fn from(error: libxml::parser::XmlParseError) -> Self {
        Error::XmlParseError { error }
    }
}

pub fn sign_xml<Bytes: AsRef<[u8]>>(xml: Bytes, private_key_der: &[u8]) -> Result<String, Error> {
    let parser = XmlParser::default();
    let document = parser.parse_string(xml)?;

    let key = XmlSecKey::from_memory(private_key_der, XmlSecKeyFormat::Der, None)?;
    let mut context = XmlSecSignatureContext::new();
    context.insert_key(key);

    context.sign_document(&document)?;

    Ok(document.to_string())
}

pub fn verify_signed_xml<Bytes: AsRef<[u8]>>(
    xml: Bytes,
    x509_cert_der: &[u8],
) -> Result<(), Error> {
    let parser = XmlParser::default();
    let document = parser.parse_string(xml)?;

    let key = XmlSecKey::from_memory(x509_cert_der, XmlSecKeyFormat::CertDer, None)?;
    let mut context = XmlSecSignatureContext::new();
    context.insert_key(key);

    let valid = context.verify_document(&document)?;

    if !valid {
        return Err(Error::InvalidSignature);
    }

    Ok(())
}

// Util
// strip out 76-width format and decode base64
pub fn decode_x509_cert(x509_cert: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let stripped = x509_cert
        .as_bytes()
        .to_vec()
        .into_iter()
        .filter(|b| !b" \n\t\r\x0b\x0c".contains(b))
        .collect::<Vec<u8>>();

    base64::decode(&stripped)
}

// 76-width base64 encoding (MIME)
pub fn mime_encode_x509_cert(x509_cert_der: &[u8]) -> String {
    data_encoding::BASE64_MIME.encode(x509_cert_der)
}

pub fn gen_saml_response_id() -> String {
    format!("id{}", uuid::Uuid::new_v4().to_string())
}

pub fn gen_saml_assertion_id() -> String {
    format!("_{}", uuid::Uuid::new_v4().to_string())
}
