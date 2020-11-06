//!
//! Central XmlSec1 Context
//!
use crate::bindings;
use crate::XmlSecResult;
use crate::XmlSecError;

use crate::lazy_static;

use std::ptr::null;
use std::sync::Mutex;


lazy_static! {
    static ref XMLSEC: Mutex<Option<XmlSecContext>> = Mutex::new(None);
}


pub fn guarantee_xmlsec_init()
{
    let mut inner = XMLSEC.lock()
        .expect("Unable to lock global xmlsec initalization wrapper");

    if inner.is_none() {
        *inner = Some(XmlSecContext::new().expect("Unable to create XmlSec context"));
    }
}


/// XmlSec Global Context
///
/// This object initializes the underlying xmlsec global state and cleans it
/// up once gone out of scope. It is checked by all objects in the library that
/// require the context to be initialized. See [`globals`][globals].
///
/// [globals]: globals
struct XmlSecContext {}


impl XmlSecContext
{
    /// Runs xmlsec initialization and returns instance of itself.
    pub fn new() -> XmlSecResult<Self>
    {
        init_xmlsec()?;
        init_crypto_app()?;
        init_crypto()?;

        Ok(Self {})
    }
}


impl Drop for XmlSecContext
{
    fn drop(&mut self)
    {
        cleanup_crypto();
        cleanup_crypto_app();
        cleanup_xmlsec();
    }
}


/// Init xmlsec library
fn init_xmlsec() -> XmlSecResult<()>
{
    let rc = unsafe { bindings::xmlSecInit() };

    if rc < 0 {
        return Err(XmlSecError::InitError);
    }
    Ok(())
}


/// Load default crypto engine if we are supporting dynamic loading for
/// xmlsec-crypto libraries. Use the crypto library name ("openssl",
/// "nss", etc.) to load corresponding xmlsec-crypto library.
fn init_crypto_app() -> XmlSecResult<()>
{
    // if bindings::XMLSEC_CRYPTO_DYNAMIC_LOADING
    // {
    //     let rc = unsafe { bindings::xmlSecCryptoDLLoadLibrary(0) };

    //     if rc < 0 {
    //         panic!("XmlSec failed while loading default crypto backend. \
    //                 Make sure that you have it installed and check shread libraries path");
    //     }
    // }

    let rc = unsafe { bindings::xmlSecOpenSSLAppInit(null()) };

    if rc < 0 {
        return Err(XmlSecError::InitCryptoBackendError);
    }

    Ok(())
}


/// Init xmlsec-crypto library
fn init_crypto() -> XmlSecResult<()>
{
    let rc = unsafe { bindings::xmlSecOpenSSLInit() };

    if rc < 0 {
        return Err(XmlSecError::InitDefaultCryptoBackendError)
    }

    Ok(())
}


/// Shutdown xmlsec-crypto library
fn cleanup_crypto()
{
    unsafe { bindings::xmlSecOpenSSLShutdown() };
}


/// Shutdown crypto library
fn cleanup_crypto_app()
{
    unsafe { bindings::xmlSecOpenSSLAppShutdown() };
}


/// Shutdown xmlsec library
fn cleanup_xmlsec()
{
    unsafe { bindings::xmlSecShutdown() };
}
