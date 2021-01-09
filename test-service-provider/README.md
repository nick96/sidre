# Test SAML Service Provider

This is a SAML SP intended for testing identity providers.

It's pretty much exactly the Flask example from OneLogin's Python SAML library: https://github.com/onelogin/python-saml.

## Usage

``` bash
docker run -p 5000:5000 -e B64_IDP_X509=$B64_IDP_X509 nick96/test-service-provider
```

The cert should be the base64 encoding of the cert in the PEM format.

By default the SP will run on port 5000, you can change this by setting the `FLASK_RUN_PORT`
in the container, you will also have th change the port mapping in the docker command.