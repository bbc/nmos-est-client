#!/usr/bin/env python3

import argparse
from NmosEst.nmosest import NmosEst

if __name__ == "__main__":

    """
    Example workflow for TLS Certificate provisioning
    1. Discover EST server (config file or DNS-SD)
    2. Request root CA
    3. Request RSA cert using external client cert
    4. Request ECDSA cert using external client cert
    4. Renew both certs
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default='bbc-0.workshop.nmos.tv')
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cacert", default='cacert.pem')
    parser.add_argument("--cert", default='certs/man1.ecdsa.product1.cert.chain.pem')
    parser.add_argument("--key", default='certs/man1.ecdsa.product1.key.pem')
    args = parser.parse_args()

    # Location of EST Server
    host = args.ip
    port = args.port

    ca_cert_path = args.cacert
    client_cert_path = args.cert
    client_key_path = args.key

    print(f'Using EST Server {host}:{port}')
    print(f'Root CA: {ca_cert_path}')
    print(f'External Certificate: {client_cert_path}')
    print(f'External Private Key: {client_key_path}')

    nmos_est_client = NmosEst(host, port, None, client_cert_path, client_key_path)

    # Get latest EST server CA certs.
    if not nmos_est_client.getCaCert(ca_cert_path):
        print('Exiting...')
        exit(1)

    # Request TLS Server certificate from EST server, using manufacturer issued client certificate for authentication
    if not nmos_est_client.getNewCert('camera-1.workshop.nmos.tv', f'rsa.test.pem.crt', f'rsa.test.pem.key',
                                      cipher_suite='rsa_2048'):
        print('Exiting...')
        exit(1)

    if not nmos_est_client.getNewCert('camera-1.workshop.nmos.tv', f'ecdsa.test.pem.crt', f'ecdsa.test.pem.key',
                                      cipher_suite='ecdsa'):
        print('Exiting...')
        exit(1)

    # # Renew TLS Server certificate from EST server, using previously issued certificate for authentication
    # if not nmos_est_client.renewCert('product1.workshop.nmos.tv', f'2.{client_cert_path}', f'2.{client_key_path}'):
    #     print('Exiting...')
    #     exit(1)
