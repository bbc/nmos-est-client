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


CACERT_PATH = 'certs/cacert.pem'
EXTERNAL_CERT_PATH = 'certs/valid-manufacturer-cert.pem'
EXTERNAL_KEY_PATH = 'certs/valid-manufacturer-cert.key'
INVALID_CERT_PATH = 'certs/invalid-manufacturer-cert.pem'
INVALID_KEY_PATH = 'certs/invalid-manufacturer-cert.key'

RESULT_RSA_CERT_PATH = 'certs/client-rsa-cert.pem'
RESULT_RSA_KEY_PATH = 'certs/client-rsa-cert.key'
RESULT_ECDSA_CERT_PATH = 'certs/client-ecdsa-cert.pem'
RESULT_ECDSA_KEY_PATH = 'certs/client-ecdsa-cert.key'


class PrintColors:
    PASS = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


class TestNmosEstServer(object):
    """Class to test the operation of an EST server, in compliance with a the NMOS specifications"""
    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.cacert = None
        self.externalClientCert = None
        self.externalClientCertKey = None
        self.invalidExternalClientCert = None
        self.invlaidExternalClientCertKey = None

        self._certificate_setup()

    def _certificate_setup(self):
        """Configure certificates"""

        with open(CACERT_PATH) as f:
            self.cacert = f.read()

    def compare_files(self, filePath1, filePath2):
        """Compare two files, returning True if the same"""

        # TODO: Check display differences in files
        # TODO: Ignore any difference that do not affect the operation of the certificate such as whitespace

        with open(filePath1) as f1:
            with open(filePath2) as f2:
                file1 = f1.read()
                file2 = f2.read()

            if file1 == file2:
                print("CA Cert is correct")
                return True
            else:
                print("File: {} is not the same as File: {}".format(filePath1, filePath2))
                print(file1)
                print(file2)

    def display_test_results(self, results):
        """Print all test results to screen"""
        if not len(results) > 0:
            print("ERROR: No Test Results to print")
            return

        for x in results:
            print("Test: {}".format(x["test_name"]))

            if x["result"]:
                print(PrintColors.PASS + "   Test Passed" + PrintColors.ENDC)
            else:
                print(PrintColors.FAIL + "   Test Failed: {}".format(x["description"]) + PrintColors.ENDC)

    def create_test_result_object(self, test_name, result, description=None):
        result = {
            "test_name": test_name,
            "result": result,
            "description": description,
        }

        return result

    def run_all_tests(self):
        testResults = []

        testResults.append(self.test_getCa())
        testResults.append(self.test_getCert())
        testResults.append(self.test_renewCert())
        testResults.append(self.test_getCert_with_no_auth())
        testResults.append(self.test_getCert_with_basic_auth())
        testResults.append(self.test_getCert_with_invalid_ext_cert())
        testResults.append(self.test_getCert_with_invalid_cipher_suite())

        return testResults

    def test_getCa(self):
        """Test that a valid Root CA in the pem format is returned when requested"""
        nmos_est_client = NmosEst(self.host, self.port, None, None, None)

        result = nmos_est_client.getCaCert('test_ca.pem')

        if not result:
            return self.create_test_result_object("Get Root CA", False, "Failed to get CA from EST Server")

        if self.compare_files('test_ca.pem', CACERT_PATH):
            return self.create_test_result_object("Get Root CA", True)
        else:
            return self.create_test_result_object("Get Root CA",
                                                  False,
                                                  "Returned CA Certificate is different to the certificate on file")

    def test_getCert(self):
        """
        Test that a valid TLS certificate is returned in the pem format, when a valid request
        is performed with correct externally issued certificate for authentication.
        The certificate should be valid for use as both a server and client certificate,
        for the correct domain and hostname.
        For both RSA and ECDSA certificates
        """
        nmos_est_client = NmosEst(self.host, self.port, CACERT_PATH, EXTERNAL_CERT_PATH, EXTERNAL_KEY_PATH)
        nmos_est_client.setImplictTrustAnchor(CACERT_PATH)

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', RESULT_RSA_CERT_PATH, RESULT_RSA_KEY_PATH, cipher_suite='rsa_2048')
        if not result:
            return self.create_test_result_object("Get Certificate",
                                                  False,
                                                  "EST Server did not returned RSA certificate")

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', RESULT_ECDSA_CERT_PATH, RESULT_ECDSA_KEY_PATH, cipher_suite='ecdsa')
        if not result:
            return self.create_test_result_object("Get Certificate",
                                                  False,
                                                  "EST Server did not returned ECDSA certificate")

        # TODO: Check the validity of the each returned certificate

        return self.create_test_result_object("Get Certificate", True)

    def test_renewCert(self):
        """
        Test that a valid TLS certificate is returned in the pem format, when a valid request
        is performed with a previously issued certificate for authentication.
        """
        nmos_est_client = NmosEst(self.host, self.port, CACERT_PATH, RESULT_RSA_CERT_PATH, RESULT_RSA_KEY_PATH)
        nmos_est_client.setImplictTrustAnchor(CACERT_PATH)

        # Should not return a certificate
        result = nmos_est_client.renewCert('test.com', 'test_cert.pem', 'test_key.pem', cipher_suite='rsa_2048')
        if not result:
            return self.create_test_result_object("Renew Certificate",
                                                  False,
                                                  "EST Server did not returned RSA certificate")

        # Should not return a certificate
        nmos_est_client.client_cert_path = RESULT_ECDSA_CERT_PATH
        nmos_est_client.client_key_path = RESULT_ECDSA_KEY_PATH
        result = nmos_est_client.renewCert('test.com', 'test_cert.pem', 'test_key.pem', cipher_suite='ecdsa')
        if not result:
            return self.create_test_result_object("Renew Certificate",
                                                  False,
                                                  "EST Server did not returned ECDSA certificate")

        # TODO: Check the validity of the each returned certificate

        return self.create_test_result_object("Renew Certificate", True)

    def test_getCert_with_no_auth(self):
        """Test that the request is rejected when no auth is provided"""

        nmos_est_client = NmosEst(self.host, self.port, CACERT_PATH, None, None)
        nmos_est_client.try_later_attempts = 0

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', 'test_cert.pem', 'test_key.pem', cipher_suite='rsa_2048')
        if result:
            return self.create_test_result_object("Get Certificate with No Authentication",
                                                  False,
                                                  "EST Server returned RSA certificate, no certificate should be returned")

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', 'test_cert.pem', 'test_key.pem', cipher_suite='ecdsa')
        if result:
            return self.create_test_result_object("Get Certificate with No Authentication",
                                                  False,
                                                  "EST Server returned ECDSA certificate, no certificate should be returned")

        return self.create_test_result_object("Get Certificate with No Authentication", True)

    def test_getCert_with_basic_auth(self):
        """Test that the request is rejected when HTTP basic auth is provided"""

        nmos_est_client = NmosEst(self.host, self.port, CACERT_PATH, None, None)
        nmos_est_client.try_later_attempts = 0
        nmos_est_client.estClient.set_basic_auth('estuser', 'estpwd')

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', 'test_cert.pem', 'test_key.pem', cipher_suite='rsa_2048')
        if result:
            return self.create_test_result_object("Get Certificate with Basic Auth",
                                                  False,
                                                  "EST servers should reject RSA request that use HTTP basic auth")

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', 'test_cert.pem', 'test_key.pem', cipher_suite='ecdsa')
        if result:
            return self.create_test_result_object("Get Certificate with Basic Auth",
                                                  False,
                                                  "EST servers should reject ECDSA request that use HTTP basic auth")

        return self.create_test_result_object("Get Certificate with Basic Auth", True)

    def test_getCert_with_invalid_ext_cert(self):
        """Test that the request is rejected when invalid external certificate is used"""
        nmos_est_client = NmosEst(self.host, self.port, CACERT_PATH, INVALID_CERT_PATH, INVALID_KEY_PATH)
        nmos_est_client.setImplictTrustAnchor(CACERT_PATH)

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', 'test', 'test.key', cipher_suite='rsa_2048')
        if result:
            return self.create_test_result_object("Get Certificate with invalid Client Certificate Authorisation",
                                                  False,
                                                  "EST Server should not return RSA certificate")

        # Should not return a certificate
        result = nmos_est_client.getNewCert('test.com', 'test', 'test.key', cipher_suite='ecdsa')
        if result:
            return self.create_test_result_object("Get Certificate with invalid Client Certificate Authorisation",
                                                  False,
                                                  "EST Server should not return ECDSA certificate")

        return self.create_test_result_object("Get Certificate with invalid Client Certificate Authorisation", True)

    def test_getCert_with_invalid_cipher_suite(self):
        """Test that the request is rejected when invalid external certificate is used"""

        return self.create_test_result_object("Get Certificate with invalid cipher suite", False)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default='localhost')
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    testEst = TestNmosEstServer(args.ip, args.port)

    testResults = testEst.run_all_tests()

    testEst.display_test_results(testResults)
