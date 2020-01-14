#!/usr/bin/env python3

import argparse
import os
from datetime import datetime as dt
import est_client_python.est.errors as est_errors
import est_client_python.est.client as est_client
import OpenSSL.crypto as openssl


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

    def _writeDataToFile(self, data, path, private=False):
        if not isinstance(data, str) and not isinstance(data, bytes):
            print(f"Cert data is not a string or bytes, file: {path}")
            return False

        if isinstance(data, bytes):
            # Convert bytes to string
            data = data.decode('ascii')

        with open(path, 'w') as f:
            f.write(data)

        if private:
            os.chmod(path, 0o400)

    def _verifyCert(self):
        """
        Check that the TLS certificate is valid, by checking the expiry date and domain for server certificate
        """

    def _createCsr(self, common_name, cipher_suite='rsa_2048'):
        # Create CSR and get private key used to sign the CSR.
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
                                                     cipher_suite=cipher_suite)

        return private_key, csr

    def getCaCert(self, newPath):
        # Get CA Cert, but do not verify the authenticity of the EST server
        try:
            ca_cert = self.estClient.cacerts()
        except est_errors.RequestError as e:
            print("Failed to get Root CA from EST Server")
            print(e)
            return

        self._writeDataToFile(ca_cert, newPath)

        # Use latest Root CA for future requests
        self.estClient.implicit_trust_anchor_cert_path = newPath

    def getNewCert(self, newPath):
        """
        Get a new TLS certificate from EST, using externally issued certificate for authentication with EST server 
        """

        # Get CSR attributes from EST server as an OrderedDict.
        csr_attrs = self.estClient.csrattrs()

        print(csr_attrs)

        private_key, csr = self._createCsr('testProduct')

        self._writeDataToFile(private_key, 'test.key', private=False)

        ext_cert = (self.ext_client_cert_path, self.ext_client_key_path)

        client_cert = self.estClient.simpleenroll(csr, ext_cert)

        self._writeDataToFile(client_cert, newPath)

        self.inspectCert(client_cert)

    def renewCert(self):
        """
        Renew existing TLS certificate, using current certificate for authentication with EST server
        """

        print('not implemented')

    def inspectCert(self, cert_data):

        cert = openssl.load_certificate(openssl.FILETYPE_PEM, cert_data)

        print(f'CA Issuer: {cert.get_issuer().get_components()[0][1]}')
        print(f'Cert Subject: {cert.get_subject()}')

        expiry_date = cert.get_notAfter()
        expiry_date = self.convertAsn1DateToString(expiry_date)

        print(f'Expiry Date: {expiry_date}')
        print('Extensions:')
        for i in range(cert.get_extension_count()):
            print(f'   {cert.get_extension(i)}')

    def convertAsn1DateToString(self, ans1_date):
        if isinstance(ans1_date, bytes):
            # Convert bytes to string
            ans1_date = ans1_date.decode('ascii')

        # Strip tailing Z from string
        if ans1_date[-1:] == 'Z':
            ans1_date = ans1_date[:-1]

        # Covert to date object
        date = dt.strptime(ans1_date, '%Y%m%d%H%M%S')

        return date



if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default='bbc-0.workshop.nmos.tv')
    parser.add_argument("--port", type=int, default=8085)
    parser.add_argument("--cacert", default='cacert.pem')
    parser.add_argument("--cert", default='manufacturer1.ecdsa.product1.cert.chain.pem')
    parser.add_argument("--key", default='manufacturer1.ecdsa.product1.key.pem')
    args = parser.parse_args()

    # Location of EST Server
    host = args.ip  # 'testrfc7030.cisco.com'
    port = args.port  # 8443

    # Root CA used to sign the EST servers Server certificate
    ca_cert_path = args.cacert
    client_cert_path = args.cert
    client_key_path = args.key

    print(f'Using EST Server {host}:{port}')
    print(f'Root CA: {ca_cert_path}')
    print(f'Client Certificate: {client_cert_path}')
    print(f'Client Key: {client_key_path}')

    nmos_est_client = NmosEst(host, port, None, client_cert_path, client_key_path)

    # Get latest EST server CA certs.
    ca_certs = nmos_est_client.getCaCert(ca_cert_path)

    nmos_est_client.getNewCert(f'est.{client_cert_path}')

    exit(0)



    """
    Example workflow of EST class
    1. Discover EST server (config file or DNS-SD)
    2. Request root CA
    3. Request RSA cert using external client cert 
    4. Request ECDSA cert using external client cert 
    4. Renew both certs
    """
