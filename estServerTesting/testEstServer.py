#!/usr/bin/env python3

import argparse


class TestNmosEstServer(object):
    """Class to test the operation of an EST server, in compliance with a the NMOS specifictions"""
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
        self.test_getCert_with_invaild_ext_cert()
        self.test_getCert_with_invaild_cipher_suite()


    def test_getCa(self):
        """Test that a valid Root CA in the pem format is returned when requested"""

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

    def test_getCert_with_invaild_ext_cert(self):
        """Test that the request is rejected when invalid external certificate is used"""

    def test_getCert_with_invaild_cipher_suite(self):
        """Test that the request is rejected when invalid external certificate is used"""


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default='ap-nuc-0.rd.bbc.co.uk')
    parser.add_argument("--port", type=int, default=8085)
    parser.add_argument("--cacert", default='cacert.pem')
    parser.add_argument("--cert", default='manufacturer1.ecdsa.product1.cert.chain.pem')
    parser.add_argument("--key", default='manufacturer1.ecdsa.product1.key.pem')
    args = parser.parse_args()

    testEst = TestNmosEstServer()


