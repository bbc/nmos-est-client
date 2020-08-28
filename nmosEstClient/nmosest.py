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
import os
from datetime import datetime as dt
from time import sleep
import estClient.est.errors as est_errors
import estClient.est.client as est_client
import OpenSSL.crypto as openssl

NUM_TRY_LATER_ATTEMPTS = 2  # Number of times request should be resent on HTTP 202-Try Later

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


PASSED = bcolors.OKGREEN + 'Passed' + bcolors.ENDC
FAILED = bcolors.FAIL + 'Failed' + bcolors.ENDC


class NmosEst(object):
    def __init__(self, host, port,
                 cacert_path,
                 client_cert_path,
                 client_key_path):
        """
        Class used to provision an NMOS Node with the Root CA and TLS Server certificate, can also be used
        to renew both when expiring.
        If a valid TLS server certificate for the current domain is not present, the externally issued client
        certificate will be used for authentication with the EST server.
        """
        self.estClient = est_client.Client(host, port, implicit_trust_anchor_cert_path=False)
        self.cacert_path = cacert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.try_later_attempts = NUM_TRY_LATER_ATTEMPTS

    def isCertValid(self, cert_data):
        """Check that the TLS certificate is valid, by checking the expiry date and domain for server certificate

        Args:
            cert_data: String of certificate data

        Returns:
            True if certificate passes all tests
        """
        cert = openssl.load_certificate(openssl.FILETYPE_PEM, cert_data)

        if cert.has_expired():
            print('Certificate has expired')
            return False

        return True

    def verifyNmosCert(self, cert_data):
        """Check that the TLS certificate is valid for use as an NMOS Server certificate.
        Validates the date and domain and certificate usage

        Args:
            cert_data: String of certificate data

        Returns:
            True if certificate passes all tests
        """
        test_results = {
            "basic_validation": False,
            "extended_key_usage": False
        }

        test_results['basic_validation'] = self.isCertValid(cert_data)

        cert = openssl.load_certificate(openssl.FILETYPE_PEM, cert_data)

        for i in range(cert.get_extension_count()):
            if cert.get_extension(i).get_short_name() == b'extendedKeyUsage':
                print('Certificate Extended Key usage:\n \
                      {}'.format(cert.get_extension(i)))
                test_results['extended_key_usage'] = True
                # if str(cert.get_extension(i)) == 'TLS Web Server Authentication, TLS Web Client Authentication':
                #     test_results['extended_key_usage'] = True
                # else:
                #     print(f'Certificate does not support Extended Key usage for both Web Server and Web Clients: \
                #           {cert.get_extension(i)}')

        cert_is_valid = True
        for test in test_results:
            result = (PASSED if test_results[test] else FAILED)
            print('Test {}: {}'.format(test, result))
            if not test_results[test]:
                cert_is_valid = False

        return cert_is_valid

    def inspectCert(self, cert_data):
        """Print information about the certificate

        Args:
            cert_data: String of certificate data

        Returns:
            None
        """

        cert = openssl.load_certificate(openssl.FILETYPE_PEM, cert_data)

        print('CA Issuer: {}'.format(cert.get_issuer().get_components()[0][1]))
        print('Cert Subject: {}'.format(cert.get_subject()))

        expiry_date = cert.get_notAfter()
        expiry_date = self.convertAsn1DateToString(expiry_date)

        print('Expiry Date: {}'.format(expiry_date))
        print('Version Number: {}'.format(cert.get_version()))
        print('Extensions:')
        for i in range(cert.get_extension_count()):
            print('   {}'.format(cert.get_extension(i)))

    def inspectCsr(self, csr_data):
        """Print information about the Certificate Signing Request PKCS10

        Args:
            csr_data: String of CSR data

        Returns:
            None
        """
        csr = openssl.load_certificate_request(openssl.FILETYPE_PEM, csr_data)

        print('Cert Subject: {}'.format(csr.get_subject()))

        print('Version Number: {}'.format(csr.get_version()))
        print('Extensions:')
        for ext in csr.get_extensions():
            print('   {}: {}'.format(ext.get_short_name(), ext))

    def convertAsn1DateToString(self, asn1_date):
        """Convert ASN.1 formated date (YYYYMMDDhhmmssZ) to datatime object"""
        if isinstance(asn1_date, bytes):
            # Convert bytes to string
            asn1_date = asn1_date.decode('utf-8')

        # Strip tailing Z from string
        if asn1_date[-1:] == 'Z':
            asn1_date = asn1_date[:-1]

        # Covert to date object
        date = dt.strptime(asn1_date, '%Y%m%d%H%M%S')

        return date

    def _createCsr(self, common_name, subject_alt_name=None, cipher_suite='rsa_2048', private_key=None):
        """Create CSR and private key

        Args:
            common_name: Common name to be included in the certificate

            subject_alt_name: Subject alternative name to be included in the certificate
                eg. b'DNS:test.com'

            cipher_suite: Cipher suite to be used to sign the CSR. rsa_2048 and ecdsa supported

        Returns:
            private_key, csr
        """
        country = 'GB'
        city = 'Manchester'
        organization = 'AMWA'
        organizational_unit = 'ENG'
        email_address = 'test@workshop.nmos.tv'
        private_key, csr = self.estClient.create_csr(common_name,
                                                     country=country,
                                                     city=city,
                                                     organization=organization,
                                                     organizational_unit=organizational_unit,
                                                     email_address=email_address,
                                                     cipher_suite=cipher_suite,
                                                     subject_alt_name=subject_alt_name,
                                                     private_key=private_key)

        # Add OID extension for certificate profile
        # profile_ext = openssl.X509Extension(b'1.3.6.1.4.1.311.20.2', False, b'pc-client')
        # csr.add_extensions([profile_ext])

        self.inspectCsr(csr)

        return private_key, csr

    def setImplictTrustAnchor(self, path):
        self.estClient.implicit_trust_anchor_cert_path = path
        self.cacert_path = path

    def getCaCert(self, newCaPath):
        """Get CA Cert, but do not verify the authenticity of the EST server"""
        try:
            ca_cert = self.estClient.cacerts()
        except est_errors.RequestError as e:
            print("Failed to get Root CA from EST Server")
            print(e)
            return False

        self._writeDataToFile(ca_cert, newCaPath)

        # Use latest Root CA for future requests
        self.setImplictTrustAnchor(newCaPath)

        return True

    def getNewCert(self, hostname, newCertPath, newKeyPath, cipher_suite='rsa_2048'):
        """
        Get a new TLS certificate from EST, using externally issued certificate for authentication with EST server
        """

        # Get CSR attributes from EST server as an OrderedDict.
        # csr_attrs = self.estClient.csrattrs()

        private_key, csr = self._createCsr(hostname, cipher_suite=cipher_suite)

        client_cert = (self.client_cert_path, self.client_key_path)

        cert_response = self._request_cert(self.estClient.simpleenroll, csr, client_cert)
        if not cert_response:
            print('Failed to request new TLS certificate')
            print('for host: {} with cipher suite: {}'.format(hostname, cipher_suite))
            return False

        # Append Chain of trust
        with open(self.cacert_path) as f:
            cert_response += f.read()

        self._writeDataToFile(private_key, newKeyPath)
        self._writeDataToFile(cert_response, newCertPath)

        self.inspectCert(cert_response)
        self.verifyNmosCert(cert_response)

        return True

    def renewCert(self, hostname, newCertPath, newKeyPath, cipher_suite='rsa_2048'):
        """
        Renew existing TLS certificate, using current certificate for authentication with EST server
        """

        # Get CSR attributes from EST server as an OrderedDict.
        # csr_attrs = self.estClient.csrattrs()

        private_key, csr = self._createCsr(hostname, cipher_suite=cipher_suite)

        client_cert = (self.client_cert_path, self.client_key_path)

        cert_response = self._request_cert(self.estClient.simplereenroll, csr, client_cert)
        if not cert_response:
            print('Failed to renew TLS certificate')
            return False

        self._writeDataToFile(private_key, newKeyPath)
        self._writeDataToFile(cert_response, newCertPath)

        self.inspectCert(cert_response)
        self.verifyNmosCert(cert_response)

        return True

    def serverKeyGen(self, hostname, newCertPath, newKeyPath, cipher_suite='rsa_2048'):
        """
        Get new certificate with the EST server generating the key pair
        """

        private_key_unused, csr = self._createCsr(hostname, cipher_suite=cipher_suite)

        client_cert = (self.client_cert_path, self.client_key_path)

        cert_response, private_key = self._request_cert(self.estClient.serverkeygen, csr, client_cert)
        if not cert_response or not private_key:
            print('Failed to renew TLS certificate')
            return False

        # Responses are base 64 encoded
        print('Cert: ' + cert_response.decode('ascii'))  # pkcs7 format
        print('Server generate key: ' + private_key.decode('ascii'))  # pkcs8 format

        # self._writeDataToFile(private_key, newKeyPath)
        # self._writeDataToFile(cert_response, newCertPath)

        # self.inspectCert(cert_response)
        # self.verifyNmosCert(cert_response)

        return True

    def _request_cert(self, method, *args):
        """Perform request and handle errors"""
        success = False
        for x in range(self.try_later_attempts):
            try:
                returned_cert = method(*args)
                success = True
                break
            except est_errors.TryLater as e:
                print('Try request certificate again in {} seconds'.format(e.seconds))
                sleep(e.seconds)
            except est_errors.RequestError as e:
                print("Failed to get TLS Certificate from EST Server")
                print(e)
                return False
        if not success:
            return False

        return returned_cert

    def _writeDataToFile(self, data, path, private=False):
        """Write data to file path"""
        if not isinstance(data, str) and not isinstance(data, bytes):
            print('Cert data is not a string or bytes, file: {}'.format(path))
            return False

        if isinstance(data, bytes):
            # Convert bytes to string
            data = data.decode('utf-8')

        with open(path, 'w') as f:
            f.write(data)

        if private:
            os.chmod(path, 0o400)


if __name__ == "__main__":

    """
    Example workflow of NMOS EST class
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

    print('Using EST Server {}:{}'.format(host, port))
    print('Root CA: {}'.format(ca_cert_path))
    print('External Certificate: {}'.format(client_cert_path))
    print('External Private Key: {}'.format(client_key_path))

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
