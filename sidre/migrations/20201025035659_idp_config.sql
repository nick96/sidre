CREATE TABLE idp_config (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4()
    , idp_id VARCHAR UNIQUE NOT NULL
    , wants_signed_request boolean NOT NULL
    , name_id_format VARCHAR NOT NULL

    , FOREIGN KEY(idp_id) REFERENCES idps(id)
);

CREATE TABLE idp_users (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4()
    , idp_id VARCHAR NOT NULL
    , name_id VARCHAR NOT NULL

    , UNIQUE(idp_id, name_id)
);

CREATE TABLE idp_user_attributes (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4()
    , user_id uuid NOT NULL
    , key VARCHAR NOT NULL
    , value VARCHAR NOT NULL

    , FOREIGN KEY(user_id) REFERENCES idp_users(id)
);