# Sidre

Dev env IdP factory.

## TODO

- [ ] IdP creation
    - [ ] Key generation (`openssl`)
    - [ ] X509 generation (`openssl`)
        - Requires key
    - [ ] IdP entity metadata generation (`libxml`)
        - [ ] Requires X509
- [ ] SP registration
    - [ ] SP entity metadata parsing (`libxml`)
- [ ] SSO handling
    - [ ] AuthnRequest parsing (`libxml`)
    - [ ] Assertion generation (`libxml`)
    - [ ] Assertion signing (`xmlsec`)   