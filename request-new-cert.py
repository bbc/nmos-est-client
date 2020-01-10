#!/usr/bin/env python3

import argparse
import est_client_python.est.errors as est_errors
import est_client_python.est.client as est_client

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    # Location of EST Server
    host = args.ip  # 'testrfc7030.cisco.com'
    port = args.port  # 8443

    # Root CA used to sign the EST servers Server certificate
    implicit_trust_anchor_cert_path = 'cacert.pem'

    client = est_client.Client(host, port, implicit_trust_anchor_cert_path)

    # Get CSR attributes from EST server as an OrderedDict.
    csr_attrs = client.csrattrs()

    # Get latest EST server CA certs.
    ca_certs = client.cacerts()

    username = 'estuser'
    password = 'estpwd'
    client.set_basic_auth(username, password)

    # Create CSR and get private key used to sign the CSR.
    common_name = 'test'
    country = 'US'
    state = 'Massachusetts'
    city = 'Boston'
    organization = 'Cisco Systems'
    organizational_unit = 'ENG'
    email_address = 'test@cisco.com'
    priv, csr = client.create_csr(common_name, country, state, city,
                                         organization, organizational_unit,
                                         email_address)

    # Enroll: get cert signed by the EST server.
    client_cert = client.simpleenroll(csr)

    print(client_cert)

    # # Re-Enroll: Renew cert.  The previous cert/key can be passed for auth if needed.
    # client_cert = client.simplereenroll(csr)
