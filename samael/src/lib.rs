pub mod attribute;
pub mod crypto;
#[cfg(feature = "usexmlsec")]
pub mod idp;
pub mod key_info;
pub mod metadata;
pub mod schema;
pub mod service_provider;
pub mod signature;

#[macro_use]
extern crate derive_builder;

#[cfg(feature = "usexmlsec")]
pub fn init() -> xmlsec::XmlSecResult<xmlsec::XmlSecSignatureContext> {
    let context = xmlsec::XmlSecSignatureContext::new()?;
    Ok(context)
}
