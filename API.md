# API

## `GET /:idp_id/metadata`

Ensure the IdP identified by `idp_id` exists. This endpoint will create the IdP
if required, otherwise the metadata will just be returned. The metadata will
always be the same.

## `POST /:idp_id/:sp_id/metadata`

Submit the SPs metadata (identified by `sp_id`) and associate it with the IdP
`idp_id`.

## `POST /:idp_id/config`

Configure IdP `idp_id`. What this will look like exactly is yet to be
determined.

## `POST /:idp_id/:sp_id/config`

Configure the SP-IDP relationship for `idp_id` and `sp_id`. What this will look
like exactly is yet to be determined.