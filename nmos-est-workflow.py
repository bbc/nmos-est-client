#!/usr/bin/env python3

# Copyright 2020 British Broadcasting Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
from nmosEstClient.nmosest import NmosEst, bcolors

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
    parser.add_argument("--ip", default='bbc-1.workshop.nmos.tv')
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cacert", default='cacert.pem')
    parser.add_argument("--cert", default='certs/man1.ecdsa.product1.cert.chain.pem')
    parser.add_argument("--key", default='certs/man1.ecdsa.product1.key.pem')
    parser.add_argument("--hostname", default='camera-1.workshop.nmos.tv')
    args = parser.parse_args()

    # Location of EST Server
    host = args.ip
    port = args.port

    ca_cert_path = args.cacert
    client_cert_path = args.cert
    client_key_path = args.key

    # Hostname of the client, to be used to generate the CSR
    hostname = args.hostname

    print('Using EST Server {}:{}'.format(host, port))
    print('Root CA: {}'.format(ca_cert_path))
    print('External Certificate: {}'.format(client_cert_path))
    print('External Private Key: {}'.format(client_key_path))

    nmos_est_client = NmosEst(host, port, None, client_cert_path, client_key_path)

    print('\n')
    print(bcolors.OKBLUE + 'Get Root CA' + bcolors.ENDC)
    # Get latest EST server CA certs.
    if not nmos_est_client.getCaCert(ca_cert_path):
        print('Exiting...')
        exit(1)

    print('\n')
    print(bcolors.OKBLUE + 'Get TLS Certificate signed with RSA Key' + bcolors.ENDC)
    # Request TLS Server certificate from EST server, using manufacturer issued client certificate for authentication
    if not nmos_est_client.getNewCert(hostname, 'rsa.test.pem.crt', 'rsa.test.pem.key',
                                      cipher_suite='rsa_2048'):
        print('Exiting...')
        exit(1)

    print('\n')
    print(bcolors.OKBLUE + 'Get TLS Certificate signed with ECDSA Key' + bcolors.ENDC)
    if not nmos_est_client.getNewCert(hostname, 'ecdsa.test.pem.crt', 'ecdsa.test.pem.key',
                                      cipher_suite='ecdsa'):
        print('Exiting...')
        exit(1)

    # Update client certificate in use
    nmos_est_client.client_cert_path = 'rsa.test.pem.crt'
    nmos_est_client.client_key_path = 'rsa.test.pem.key'

    print('\n')
    print(bcolors.OKBLUE + 'Renew TLS Certificate signed with RSA Key' + bcolors.ENDC)
    # Renew TLS Server certificate from EST server, using previously issued certificate for authentication
    if not nmos_est_client.renewCert(hostname, 'rsa.test-renew.pem.crt', 'rsa.test-renew.pem.key',
                                     cipher_suite='rsa_2048'):
        print('Exiting...')
        exit(1)
