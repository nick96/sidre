use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::X509};
use chrono::{DateTime, Duration, Utc};
use crate::error::Error;


pub fn generate_cert() -> Result<(X509, Vec<u8>, DateTime<Utc>), Error> {
    let expiry = Utc::now() + Duration::days(365);
    let rsa = Rsa::generate(4096)?;
    let pk = PKey::from_rsa(rsa.clone())?;

    let mut builder = X509::builder()?;

    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(expiry.timestamp())?.as_ref())?;
    builder.set_version(2)?;

    let pub_key = PKey::public_key_from_der(&pk.public_key_to_der()?)?;
    builder.set_pubkey(&pub_key)?;
    builder.sign(&pk, MessageDigest::sha256())?;

    let x509 = builder.build();
    let priv_key = rsa.private_key_to_der()?;
    Ok((x509, priv_key, expiry))
}

#[cfg(test)]
mod test {
    use super::generate_cert;
    use openssl::{x509::X509, rsa::Rsa, pkey::PKey};
    #[test]
    fn generate_valid_cert() {
        let (cert, pk, _) = generate_cert().unwrap();
        X509::from_der(&cert.to_der().unwrap()).unwrap();
        let rsa = Rsa::private_key_from_der(&pk).unwrap();
        let _ = PKey::from_rsa(rsa).unwrap();
    }
}