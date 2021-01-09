#!/usr/bin/env python3

import json
import os
import base64
import subprocess

b64_cert = os.environ["B64_IDP_X509"]
settings_path = "saml/settings.json"

with open(settings_path) as fh:
    settings = json.load(fh)

settings["idp"]["x509cert"] = b64_cert

with open(settings_path, "w") as fh:
    json.dump(settings, fh)

subprocess.run(["flask", "run", "-h", "0.0.0.0"])