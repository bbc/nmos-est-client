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

    def _certificate_setup(self):
        """Configure certificates"""
        # Check if certificate directory exists
        if True:
            return

        # Generate externally trusted CA and client certificate

        # Generate invalid externally trusted CA and client certificate

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

        nmos_est_client.getCaCert('ca.pem')

        return self.create_test_result_object("Get Root CA", False)

    def test_getCert(self):
        """
        Test that a valid TLS certificate is returned in the pem format, when a valid request
        is performed with correct externally issued certificate for authentication.
        The certificate should be valid for use as both a server and client certificate,
        for the correct domain and hostname.
        For both RSA and ECDSA certificates
        """

        return self.create_test_result_object("Get Certificate", False)

    def test_renewCert(self):
        """
        Test that a valid TLS certificate is returned in the pem format, when a valid request
        is performed with a previously issued certificate for authentication.
        """

        return self.create_test_result_object("Renew Certificate", False)

    def test_getCert_with_no_auth(self):
        """Test that the request is rejected when no auth is provided"""

        return self.create_test_result_object("Get Certificate with No Authentication", False)

    def test_getCert_with_basic_auth(self):
        """Test that the request is rejected when HTTP basic auth is provided"""

        return self.create_test_result_object("Get Certificate with Basic Auth", False,
                                              "EST servers should reject request that use HTTP basic auth")

    def test_getCert_with_invalid_ext_cert(self):
        """Test that the request is rejected when invalid external certificate is used"""

        return self.create_test_result_object("Get Certificate with invalid Client Certificate Authorisation", False)

    def test_getCert_with_invalid_cipher_suite(self):
        """Test that the request is rejected when invalid external certificate is used"""

        return self.create_test_result_object("Get Certificate with invalid cipher suite", False)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default='bbc-1.workshop.nmos.tv')
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    testEst = TestNmosEstServer(args.ip, args.port)

    testResults = testEst.run_all_tests()

    testEst.display_test_results(testResults)
