CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE idps (
      -- IdPs ID. This is referenced in the URL.
      id VARCHAR PRIMARY KEY
      -- X509 certificate.
    , certificate BYTEA NOT NULL
      -- Private key associated with the cert.
    , private_key BYTEA NOT NULL
    , entity_id VARCHAR NOT NULL
    , metadata_valid_until TIMESTAMPTZ NOT NULL
    , name_id_format VARCHAR NOT NULL
    , redirect_url VARCHAR NOT NULL
);

CREATE TABLE sps (
    -- SP's ID. This is references in the the URL.
      id VARCHAR PRIMARY KEY
);

CREATE TABLE idps_x_sps (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4()
    , idp_id VARCHAR NOT NULL
    , sp_id VARCHAR NOT NULL
    
    , FOREIGN KEY(idp_id) REFERENCES idps(id)
    , FOREIGN KEY(sp_id) REFERENCES sps(id)
    , UNIQUE(idp_id, sp_id)
);