//!
//! Wrapper for DSIG Nodes Templating
//!
use crate::bindings;

use crate::XmlDocument;

use crate::XmlSecCanonicalizationMethod;
use crate::XmlSecSignatureMethod;

use crate::XmlSecError;
use crate::XmlSecResult;

use std::ffi::CString;
use std::ptr::null;
use std::os::raw::c_uchar;


/// Declaration of a template building API for other specific trait extensions
/// on foreign XML objects.
pub trait TemplateBuilder
{
    /// Sets canonicalization method. See: [`XmlSecCanonicalizationMethod`][c14n].
    ///
    /// [c14n]: ./transforms/enum.XmlSecCanonicalizationMethod.html
    fn canonicalization(self, c14n: XmlSecCanonicalizationMethod) -> Self;

    /// Sets cryptographic signature method. See: [`XmlSecSignatureMethod`][sig].
    ///
    /// [sig]: ./crypto/openssl/enum.XmlSecSignatureMethod.html
    fn signature(self, sig: XmlSecSignatureMethod) -> Self;

    /// Sets signature subject node URI
    fn uri(self, uri: &str) -> Self;

    /// Adds <ds:KeyName> to key information node
    fn keyname(self, add: bool) -> Self;

    /// Adds <ds:KeyValue> to key information node
    fn keyvalue(self, add: bool) -> Self;

    /// Adds <ds:X509Data> to key information node
    fn x509data(self, add: bool) -> Self;

    /// Builds the actual template and returns
    fn done(self) -> XmlSecResult<()>;
}


/// Trait extension aimed at a concrete implementation for [`XmlDocument`][xmldoc]
///
/// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
pub trait XmlDocumentTemplating<'d>
{
    /// Return a template builder over current XmlDocument.
    fn template(&'d self) -> XmlDocumentTemplateBuilder<'d>;
}


/// Concrete template builder for [`XmlDocument`][xmldoc]
///
/// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
pub struct XmlDocumentTemplateBuilder<'d>
{
    doc:     &'d XmlDocument,
    options: TemplateOptions,
}


struct TemplateOptions
{
    c14n: XmlSecCanonicalizationMethod,
    sig:  XmlSecSignatureMethod,

    uri: Option<String>,

    keyname:  bool,
    keyvalue: bool,
    x509data: bool,
}


impl Default for TemplateOptions
{
    fn default() -> Self
    {
        Self {
            c14n: XmlSecCanonicalizationMethod::ExclusiveC14N,
            sig:  XmlSecSignatureMethod::RsaSha1,

            uri: None,

            keyname:  false,
            keyvalue: false,
            x509data: false,
        }
    }
}


impl<'d> XmlDocumentTemplating<'d> for XmlDocument
{
    fn template(&'d self) -> XmlDocumentTemplateBuilder<'d>
    {
        crate::xmlsec::guarantee_xmlsec_init();

        XmlDocumentTemplateBuilder {doc: self, options: TemplateOptions::default()}
    }
}


impl<'d> TemplateBuilder for XmlDocumentTemplateBuilder<'d>
{
    fn canonicalization(mut self, c14n: XmlSecCanonicalizationMethod) -> Self
    {
        self.options.c14n = c14n;
        self
    }

    fn signature(mut self, sig: XmlSecSignatureMethod) -> Self
    {
        self.options.sig = sig;
        self
    }

    fn uri(mut self, uri: &str) -> Self
    {
        self.options.uri = Some(uri.to_owned());
        self
    }

    fn keyname(mut self, add: bool) -> Self
    {
        self.options.keyname = add;
        self
    }

    fn keyvalue(mut self, add: bool) -> Self
    {
        self.options.keyvalue = add;
        self
    }

    fn x509data(mut self, add: bool) -> Self
    {
        self.options.x509data = add;
        self
    }

    fn done(self) -> XmlSecResult<()>
    {
        let curi = {
            if let Some(uri) = self.options.uri {
                CString::new(uri).map_err(|_| XmlSecError::CStringError)?.into_raw() as *const c_uchar
            } else {
                null()
            }
        };

        // let curi = self.options.uri.map(|p| CString::new(p).unwrap());

        let docptr = self.doc.doc_ptr() as *mut bindings::xmlDoc;

        let rootptr;
        if let Some(root) = self.doc.get_root_element() {
            rootptr = root.node_ptr() as *mut bindings::xmlNode;
        } else {
            return Err(XmlSecError::RootNotFound);
        }

        let signature = unsafe { bindings::xmlSecTmplSignatureCreate(
            docptr,
            self.options.c14n.to_method(),
            self.options.sig.to_method(),
            null()
        ) };

        if signature.is_null() {
            return Err(XmlSecError::SignatureTemplateCreationError);
        }

        let reference = unsafe { bindings::xmlSecTmplSignatureAddReference(
            signature,
            XmlSecSignatureMethod::Sha1.to_method(),
            null(),
            curi,
            null()
        ) };

        if reference.is_null() {
            return Err(XmlSecError::AddEnvelopedTransformToReferenceError);
        }

        let envelope = unsafe { bindings::xmlSecTmplReferenceAddTransform(reference, bindings::xmlSecTransformEnvelopedGetKlass()) };

        if envelope.is_null() {
            return Err(XmlSecError::AddEnvelopedTransformError);
        }

        let keyinfo = unsafe { bindings::xmlSecTmplSignatureEnsureKeyInfo(signature, null()) };

        if keyinfo.is_null() {
            return Err(XmlSecError::KeyInfoError);
        }

        if self.options.keyname
        {
            let keyname = unsafe { bindings::xmlSecTmplKeyInfoAddKeyName(keyinfo, null()) };

            if keyname.is_null() {
                return Err(XmlSecError::KeyNameError);
            }
        }

        if self.options.keyvalue
        {
            let keyvalue = unsafe { bindings::xmlSecTmplKeyInfoAddKeyValue(keyinfo) };

            if keyvalue.is_null() {
                return Err(XmlSecError::KeyValueError);
            }
        }

        if self.options.x509data
        {
            let x509data = unsafe { bindings::xmlSecTmplKeyInfoAddX509Data(keyinfo) };

            if x509data.is_null() {
                return Err(XmlSecError::KeyValueError);
            }
        }

        unsafe { bindings::xmlAddChild(rootptr, signature) };

        if ! curi.is_null() {
            unsafe { CString::from_raw(curi as *mut i8); }
        }

        Ok(())
    }
}
