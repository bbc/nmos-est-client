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
from nmosEstClient.nmosest import NmosEst


class TestNmosEstServer(object):
    """Class to test the operation of an EST server, in compliance with a the NMOS specifications"""
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def _certificate_setup(self):
        """Configure certificates"""
        # Check if certificate directory exists
        if True:
            return

        # Generate externally trusted CA and client certificate

        # Generate invalid externally trusted CA and client certificate

    def run_all_tests(self):
        self.test_getCa()
        self.test_getCert()
        self.test_renewCert()
        self.test_getCert_with_no_auth()
        self.test_getCert_with_basis_auth()
        self.test_getCert_with_invalid_ext_cert()
        self.test_getCert_with_invalid_cipher_suite()

    def test_getCa(self):
        """Test that a valid Root CA in the pem format is returned when requested"""
        nmos_est_client = NmosEst(self.host, self.port, None, None, None)

        nmos_est_client.getCaCert('ca.pem')

    def test_getCert(self):
        """
        Test that a valid TLS certificate is returned in the pem format, when a valid request
        is performed with correct externally issued certificate for authentication.
        The certificate should be valid for use as both a server and client certificate,
        for the correct domain and hostname.
        For both RSA and ECDSA certificates
        """

    def test_renewCert(self):
        """
        Test that a valid TLS certificate is returned in the pem format, when a valid request
        is performed with a previously issued certificate for authentication.
        """

    def test_getCert_with_no_auth(self):
        """Test that the request is rejected when no auth is provided"""

    def test_getCert_with_basis_auth(self):
        """Test that the request is rejected when HTTP basic auth is provided"""

    def test_getCert_with_invalid_ext_cert(self):
        """Test that the request is rejected when invalid external certificate is used"""

    def test_getCert_with_invalid_cipher_suite(self):
        """Test that the request is rejected when invalid external certificate is used"""


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default='bbc-1.workshop.nmos.tv')
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    testEst = TestNmosEstServer(args.ip, args.port)

    testEst.run_all_tests()
