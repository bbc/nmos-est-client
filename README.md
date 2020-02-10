
# Enrolment over Secure Transport (EST)

EST is a protocol for requesting X.509 certificates over HTTPS, the EST Client is the device requesting the certificate and the EST server listens for certificate requests at a well known path.

EST RFC: https://tools.ietf.org/html/rfc7030

An example EST server can be found here: http://testrfc7030.com/

Contents
========

* [estClient](estClient) - EST Client Python library for requesting certificates using the EST endpoint
    * This a modified version of this library, with support for ECDSA key profiles added
* [nmosEstClient](nmosEstClient) - NMOS EST Client Python library, that abstract the required NMOS specific functinality of EST defined in https://github.com/AMWA-TV/nmos-api-security
* [nmos-est-workflow.py](nmos-est-workflow.py) - Example of NMOS workflow, for getting Root CA, TLS Server Certificate and Renewing the Certificate


Getting Started
===============

1. Clone python EST client library
```
git clone git@github.com:bbc/rd-apmm-nmos-est.git --recursive
```
2. Enable python virtual env
```
python3 -m venv env
source env/bin/activate
```
2. Install dependencies
```
pip3 install -r requirements.txt
```

Run script
```
python3 nmos-est-workflow.py --ip localhost --port 8443
```

Deactivate virtual env
```
deactivate
```

Tests (Work in Progress)
========================

In order to check the compliance of a EST Servers configuration an automated test script has been written.

The EST Server is test under normal operation for:
* The EST server correctly returns the latest Root CA
* The EST server correctly issues an RSA TLS server certificate
    * Using the Manufacturer issued client certificate for authentication and authorisation
* The EST server correctly issues an RSA TLS server certificate
    * Using the previously issued client certificate for authentication and authorisation
* The EST server correctly issues an ECDSA TLS server certificate
    * Using the Manufacturer issued client certificate for authentication and authorisation
* The EST server correctly issues an ECDSA TLS server certificate
    * Using the previously issued client certificate for authentication and authorisation

The EST Server is test under incorrect operation for:
* The EST server does not issue an TLS certificate
    * When the EST client presents a rogue manufacturer's signed client certificate
* The EST server does not issue a TLS certificate if a non permitted cipher suite is requested

#### Running Tests

```
python3 testEstServer.py --ip localhost --port 8443
```


Updating submodule
==================

```
git submodule update --remote
```
