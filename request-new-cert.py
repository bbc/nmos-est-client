#!/usr/bin/env python3

import argparse
import os
from datetime import datetime as dt
from time import sleep
import est_client_python.est.errors as est_errors
import est_client_python.est.client as est_client
import OpenSSL.crypto as openssl

NUM_TRY_LATER_ATTEMPTS = 2  # Number of times request should be resent on HTTP 202-Try Later


class NmosEst(object):
    def __init__(self, host, port,
                 cacert_path,
                 ext_client_cert_path,
                 ext_client_key_path,
                 server_cert_path=None,
                 server_key_path=None):
        """
        Class used to provision an NMOS Node with the Root CA and TLS Server certificate, can also be used
        to renew both when expiring.
        If a valid TLS server certificate for the current domain is not present, the externally issued client
        certificate will be used for authentication with the EST server.
        """
        self.estClient = est_client.Client(host, port, implicit_trust_anchor_cert_path=False)
        self.cacert_path = cacert_path
        self.ext_client_cert_path = ext_client_cert_path
        self.ext_client_key_path = ext_client_key_path
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path

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
                print(f'Certificate Extended Key usage:\n \
                      {cert.get_extension(i)}')
                test_results['extended_key_usage'] = True
                # if str(cert.get_extension(i)) == 'TLS Web Server Authentication, TLS Web Client Authentication':
                #     test_results['extended_key_usage'] = True
                # else:
                #     print(f'Certificate does not support Extended Key usage for both Web Server and Web Clients: \
                #           {cert.get_extension(i)}')

        cert_is_valid = True
        for test in test_results:
            result = ('Passed' if test_results[test] else 'Failed')
            print(f'Test {test}: {result}')
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

        print(f'CA Issuer: {cert.get_issuer().get_components()[0][1]}')
        print(f'Cert Subject: {cert.get_subject()}')

        expiry_date = cert.get_notAfter()
        expiry_date = self.convertAsn1DateToString(expiry_date)

        print(f'Expiry Date: {expiry_date}')
        print(f'Verison Number: {cert.get_version()}')
        print('Extensions:')
        for i in range(cert.get_extension_count()):
            print(f'   {cert.get_extension(i)}')

    def inspectCsr(self, csr_data):
        """Print information about the Certificate Signing Request PKCS10

        Args:
            csr_data: String of CSR data

        Returns:
            None
        """
        csr = openssl.load_certificate_request(openssl.FILETYPE_PEM, csr_data)

        print(f'Cert Subject: {csr.get_subject()}')

        print(f'Version Number: {csr.get_version()}')
        print('Extensions:')
        for ext in csr.get_extensions():
            print(f'   {ext.get_short_name()}: {ext}')

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

    def _createCsr(self, common_name, subject_alt_name=None, cipher_suite='rsa_2048'):
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
                                                     subject_alt_name=subject_alt_name)

        # Add OID extension for certificate profile
        # profile_ext = openssl.X509Extension(b'1.3.6.1.4.1.311.20.2', False, b'pc-client')
        # csr.add_extensions([profile_ext])

        self.inspectCsr(csr)

        return private_key, csr

    def setImplictTrustAnchor(self, path):
        self.estClient.implicit_trust_anchor_cert_path = path

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

        ext_cert = (self.ext_client_cert_path, self.ext_client_key_path)

        #cert_response = self._request_cert(self.estClient.simpleenroll, csr)

        cert_response = self._request_cert(self.estClient.simpleenroll, csr, ext_cert)
        if not cert_response:
            print('Failed to request new TLS certificate')
            return False

        self._writeDataToFile(private_key, newKeyPath)
        self._writeDataToFile(cert_response, newCertPath)

        # Update certificate and key path
        self.server_key_path = newKeyPath
        self.server_cert_path = newCertPath

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

        cert = (self.server_cert_path, self.server_key_path)

        cert_response = self._request_cert(self.estClient.simplereenroll, csr, cert)
        if not cert_response:
            print('Failed to renew TLS certificate')
            return False

        # Update certificate and key path
        self.server_key_path = newKeyPath
        self.server_cert_path = newCertPath

        self._writeDataToFile(private_key, newKeyPath)
        self._writeDataToFile(cert_response, newCertPath)

        self.inspectCert(cert_response)
        self.verifyNmosCert(cert_response)

        return True

    def _request_cert(self, method, *args):
        """Perform request and handle errors"""
        success = False
        for x in range(NUM_TRY_LATER_ATTEMPTS):
            try:
                returned_cert = method(*args)
                success = True
                break
            except est_errors.TryLater as e:
                print(f'Try request certificate again in {e.seconds} seconds')
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
            print(f"Cert data is not a string or bytes, file: {path}")
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
    parser.add_argument("--port", type=int, default=8085)
    parser.add_argument("--cacert", default='cacert.pem')
    parser.add_argument("--cert", default='manufacturer1.ecdsa.product1.cert.chain.pem')
    parser.add_argument("--key", default='manufacturer1.ecdsa.product1.key.pem')
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
    if not nmos_est_client.getNewCert('camera-1.workshop.nmos.tv', f'rsa.test.pem.crt', f'rsa.test.pem.key', cipher_suite='rsa_2048'):
        print('Exiting...')
        exit(1)

    if not nmos_est_client.getNewCert('camera-1.workshop.nmos.tv', f'ecdsa.test.pem.crt', f'ecdsa.test.pem.key', cipher_suite='ecdsa'):
        print('Exiting...')
        exit(1)

    # # Renew TLS Server certificate from EST server, using previously issued certificate for authentication
    # if not nmos_est_client.renewCert('product1.workshop.nmos.tv', f'2.{client_cert_path}', f'2.{client_key_path}'):
    #     print('Exiting...')
    #     exit(1)
