#!/usr/bin/env python3

import json
import os
import base64
import subprocess

b64_cert = os.environ["B64_IDP_X509"]
sp_entity_id = os.environ["SP_ENTITY_ID"]
idp_entity_id = os.environ["IDP_ENTITY_ID"]
idp_host = os.environ["IDP_HOST"]

settings_path = "saml/settings.json"

with open(settings_path) as fh:
    settings = json.load(fh)

settings["idp"]["x509cert"] = b64_cert
settings["idp"]["entityId"] = idp_entity_id
settings["idp"]["singleSignOnService"]["url"] = f"{idp_host}/{idp_entity_id}/sso"
settings["idp"]["singleLogoutService"]["url"] = f"{idp_host}/{idp_entity_id}/ssl"

settings["sp"]["entityId"] = sp_entity_id

settings_json = json.dumps(settings, indent=4)

with open(settings_path, "w") as fh:
    fh.write(settings_json)

os.environ["FLASK_ENV"] = os.environ.get("FLASK_ENV", "development")

print(f"Settings: {settings_json}")
subprocess.run(["flask", "run", "-h", "0.0.0.0"])