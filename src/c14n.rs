// This is an implementation exclusive [XML
// canonicalization](https://www.w3.org/TR/xml-exc-c14n/).
use crate::error::Error;

use xmlsec::XmlSecTemplateBuilder;
use xmlsec::XmlSecDocumentTemplating;
use xmlsec::XmlSecCanonicalizationMethod;
use xmlsec::XmlSecSignatureMethod;

use xmlsec::XmlSecKey;
use xmlsec::XmlSecKeyFormat;
use xmlsec::XmlSecSignatureContext;

use xmlsec::XmlSecDocumentExt;

use libxml::parser::Parser           as XmlParser;
use libxml::tree::document::Document as XmlDocument;


pub fn sign(document: String, pk: &[u8]) -> Result<String, Error> {
    let parser = XmlParser::default();
    let doc = parser.parse_string(document.into());
    doc.template(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        .done()?;
    
    let key = XmlSecKey::from_memory(pk, XmlSecKeyFormat::Pem, None)?;
    let mut ctx = XmlSecKeyFormat::new();
    ctx.insert_key(key);
    ctx.sign_document(doc)?;
    
}