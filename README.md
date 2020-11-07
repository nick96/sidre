# Sidre - An identity provider factory

:construction: Sidre is still under development. You're welcome to contribute but
it's not ready for use! :construction:

For what needs to be done see the [TODO file](./TODO.md) or the TODOs in the
codebase.

## Motivation

Using SSO has many benefits for users and developers alike, but it can be
difficult to test properly, often different identity providers have different
configurations and integration testing is difficult because you don't have
control over them. Sidre aims to provide an interface where you can
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

## Getting started

The expected high level usage for sidre is:

- Request the metadata for an Identity Provider (IdP) identified by some ID.
  This creates the IdP if it doesn’t exist, otherwise just returns it’s metadata
  (`GET /:idp_id/metadata`)
- Register the IdP in the Service Provider (SP) with the IdP metadata
- Post the SP metadata to an endpoint that will associate the created IdP with
  the SP (`POST /:idp_id/:sp_id/metadata`)
- Do some setup within the SP to register the IdP
- Submit configuration updates for the IdP or SP-IdP relationship (:warning: Not
  yet implemented :warning:) (`POST /:idp_id/config` and `POST
  /:idp_id/:sp_id/config` respectively)

See the [API docs](API.md) for more information about the different endpoints.

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
