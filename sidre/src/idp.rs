use openssl::{pkey::{PKey, Private}, x509::X509};
use crate::templates::NameIDFormat;

pub struct IdP {
    id: String,
    private_key: PKey<Private>,
    certificate: X509,
    entity_id: String,
    name_id_format: NameIDFormat,
}
