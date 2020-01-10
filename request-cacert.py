#!/usr/bin/env python3

import argparse
import est_client_python.est.client as est_client
import est_client_python.est.errors as est_errors

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    # Location of EST Server
    host = args.ip  # 'testrfc7030.cisco.com'
    port = args.port  # 8443

    client = est_client.Client(host, port, implicit_trust_anchor_cert_path=False)

    # Get CA Cert, but do not verify the authenticity of the EST server
    try:
        ca_cert = client.cacerts()
    except est_errors.RequestError as e:
        print("Failed to get Root CA from EST Server")
        print(e)
        exit(1)

    if not isinstance(ca_cert, str):
        print("Root CA is not a string")
        exit(1)

    print(ca_cert)

    with open('cacert.pem', 'w') as f:
        f.write(ca_cert)
