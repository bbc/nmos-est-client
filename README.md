
# Enrolment over Secure Transport (EST)

EST is a protocol for requesting X.509 certificates over HTTPS, the EST client is the device requesting the certificate and the EST server listens for certificate requests at a well known path. 

https://tools.ietf.org/html/rfc7030

An example EST server can be found here: http://testrfc7030.com/

Contents
========

* EST Client Python library for requesting certificates using the EST endpoint



Getting Started
===============

1. Clone python EST client library
```
git clone git@github.com:bbc/rd-apmm-est-client-python.git est_client_python
```
2. 
In order to check the compliance of a EST Servers configuration an automated test script has been written.

Tests
=====

The EST Server is test under normal operation for:
* The EST server correctly returns the latest Root CA
* The EST server correctly issues an RSA TLS client certificate
    * Using the Manufacturer issued client certificate for authentication and authorisation
* The EST server correctly issues an RSA TLS client certificate
    * Using the previously issued client certificate for authentication and authorisation
* The EST server correctly issues an ECDSA TLS client certificate
    * Using the Manufacturer issued client certificate for authentication and authorisation
* The EST server correctly issues an ECDSA TLS client certificate
    * Using the previously issued client certificate for authentication and authorisation
* The EST server correctly issues an RSA TLS server certificate
    * Using the Manufacturer issued client certificate for authentication and authorisation
* The EST server correctly issues an RSA TLS server certificate
    * Using the previously issued client certificate for authentication and authorisation
* The EST server correctly issues an ECDSA TLS server certificate
    * Using the Manufacturer issued client certificate for authentication and authorisation
* The EST server correctly issues an ECDSA TLS server certificate
    * Using the previously issued client certificate for authentication and authorisation

The EST Server is test under incorrect operation for:
* The EST server does not issue an TLS client/server certificate
    * When the EST client present a rogue manufacturers signed client certificate
* The EST server does not issue a TLS client/server certificate if a non permitted cipher suite is requested


* Test that certificates for same subject name can be issued with different key pairs (ECDSA and RSA) without revoking either certificate

Running Tests
=============

