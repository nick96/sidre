//!
//! XmlSec High Level Error handling
//!


/// Wrapper project-wide Result typealias.
pub type XmlSecResult<T> = Result<T, XmlSecError>;


/// Wrapper project-wide Errors enumeration.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum XmlSecError
{
    Str(String),

    KeyNotLoaded,
    KeyLoadError,
    CertLoadError,

    RootNotFound,
    NodeNotFound,

    SigningError,
    VerifyError,

    SignatureTemplateCreationError,
    AddEnvelopedTransformToReferenceError,
    AddEnvelopedTransformError,
    KeyInfoError,
    KeyNameError,
    KeyValueError,

    DSigContextError,
    UnknownDSigStatusCode,

    InitCryptoBackendError,
    InitError,
    InitDefaultCryptoBackendError,

    CStringError,
}


impl std::fmt::Display for XmlSecError
{
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        match self
        {   Self::Str(reason) => write!(fmt, "{}", reason),

            Self::KeyNotLoaded  => write!(fmt, "{}", "Key has not yet been loaded and is required"),
            Self::KeyLoadError  => write!(fmt, "{}", "Failed to load key"),
            Self::CertLoadError => write!(fmt, "{}", "Failed to load certificate"),

            Self::RootNotFound => write!(fmt, "{}", "Failed to find document root"),
            Self::NodeNotFound => write!(fmt, "{}", "Failed to find node"),

            Self::SigningError => write!(fmt, "{}", "An error has ocurred while attemting to sign document"),
            Self::VerifyError  => write!(fmt, "{}", "Verification process failed"),

            Self::SignatureTemplateCreationError => write!(fmt, "{}", "Failed to create signature template"),
            Self::AddEnvelopedTransformToReferenceError => write!(fmt, "{}", "Failed to add enveloped transform to reference"),
            Self::AddEnvelopedTransformError => write!(fmt, "{}", "Failed to add enveloped transform"),
            Self::KeyInfoError => write!(fmt, "{}", "Failed to ensure key info"),
            Self::KeyNameError => write!(fmt, "{}", "Failed to add key name"),
            Self::KeyValueError => write!(fmt, "{}", "Failed to add key value"),

            Self::DSigContextError => write!(fmt, "{}", "Failed to create dsig context"),
            Self::UnknownDSigStatusCode => write!(fmt, "{}", "Failed to interpret xmlSecDSigStatus code"),

            Self::InitCryptoBackendError => write!(fmt, "{}", "XmlSec failed to init crypto backend"),
            Self::InitError => write!(fmt, "{}", "XmlSec failed initialization"),
            Self::InitDefaultCryptoBackendError => write!(fmt, "{}", "XmlSec failed while loading default crypto backend. \
               Make sure that you have it installed and check shared libraries path"),

            Self::CStringError => write!(fmt, "{}", "Failed to create CString as it contains a nul byte"),
        }
    }
}


impl std::error::Error for XmlSecError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
    {
        None
    }
}


impl From<&str> for XmlSecError
{
    fn from(other: &str) -> Self
    {
        Self::Str(other.to_owned())
    }
}


impl From<String> for XmlSecError
{
    fn from(other: String) -> Self
    {
        Self::Str(other)
    }
}
