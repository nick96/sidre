# Sidre - An identity provider factory

## Motivation

Using SSO has many benefits for users and developers alike, but it can be
difficult to test properly, often different identity providers have different
configurations and integration testing is difficult because you don't have
control over them. Dinglehopper AIMs to provide an interface where you can
easily and programmatically provision IdPs with different configurations and
configure their relationship with service providers.

## Goals

- Provision IdPs on demand (when metadata is requested)
- Highly configurable IdPs
- Highly configurable Idp-SP relationships

## Non-goals

- Full SAML compliance
    - Just go so far as emulating normal behavior of common IdPs (SAML is big
      and hairy)
- Proper security - This isn't intended for use as an actual production IdP

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.