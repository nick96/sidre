CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE idps (
      id VARCHAR PRIMARY KEY
    , certificate BYTEA NOT NULL
    , private_key BYTEA NOT NULL
    , entity_id VARCHAR NOT NULL
    , metadata_valid_until TIMESTAMPTZ NOT NULL
    , name_id_format VARCHAR NOT NULL
    , redirect_url VARCHAR NOT NULL
    , created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    , modified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sps (
        id VARCHAR PRIMARY KEY
      , entity_id VARCHAR NOT NULL
      , name_id_format VARCHAR NOT NULL
      , consume_endpoint VARCHAR NOT NULL
      , created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      , modified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sp_keys (
        id uuid PRIMARY KEY DEFAULT uuid_generate_v4()
      , sp_id VARCHAR NOT NULL
      , key BYTEA NOT NULL
      , created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      , modified_at TIMESTAMPTZ NOT NULL DEFAULT now()
      
      , FOREIGN KEY(sp_id) REFERENCES sps(id)
      , UNIQUE(sp_id, key)

);

CREATE TABLE idps_x_sps (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4()
    , idp_id VARCHAR NOT NULL
    , sp_id VARCHAR NOT NULL
    , created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    , modified_at TIMESTAMPTZ NOT NULL DEFAULT now()
    
    , FOREIGN KEY(idp_id) REFERENCES idps(id)
    , FOREIGN KEY(sp_id) REFERENCES sps(id)
    , UNIQUE(idp_id, sp_id)
);