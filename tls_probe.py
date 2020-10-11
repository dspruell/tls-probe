'Probe SSL/TLS service to return connection and certificate details'

import argparse
from json import dumps as json_dumps
import logging
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from tabulate import tabulate


RELEVANT_EXTS = [
    'subjectAltName',
]

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(message)s'
)


def get_sock_info(addr, json=False, validate=True):
    '''
    Return SSL/TLS socket info for addr (tuple of host and port).

    Negotiate socket without requiring strict verification so that connection
    can be established and certificate data collected even in cases where
    certificate verification fails.

    XXX Sample endpoints for testing:
    - valid:   content.portal.jask.ai:443
    - valid:   www.example.com:443
    - invalid: 40.85.147.123:3389

    See also https://badssl.com/

    '''
    context = ssl.create_default_context()
    context.check_hostname = True if validate else False
    context.verify_mode = ssl.CERT_REQUIRED if validate else ssl.CERT_NONE

    with socket.create_connection(addr) as sock:
        conn_info = dict(
            conn={}, cert={'fingerprints': {}, 'extensions': {}}
        )
        with context.wrap_socket(sock, server_hostname=addr[0]) as ssock:
            cert = ssock.getpeercert(binary_form=True)
            cert_data = x509.load_der_x509_certificate(cert, default_backend())
            conn_info['conn'].update({
                'version': ssock.version(),
                'remote_addr': ':'.join([str(_) for _ in ssock.getpeername()])
            })
            conn_info['cert'].update({
                'issuer': cert_data.issuer.rfc4514_string(),
                'subject': cert_data.subject.rfc4514_string(),
                'serial': cert_data.serial_number,
                'version': cert_data.version.name,
                'signature_hash': cert_data.signature_hash_algorithm.name,
                'not_valid_before': str(cert_data.not_valid_before),
                'not_valid_after': str(cert_data.not_valid_after),
            })
            conn_info['cert']['fingerprints'].update({
                'md5': cert_data.fingerprint(hashes.MD5()).hex(),
                'sha1': cert_data.fingerprint(hashes.SHA1()).hex(),
                'sha256': cert_data.fingerprint(hashes.SHA256()).hex(),
            })
            for ext in cert_data.extensions:
                if ext.oid._name in RELEVANT_EXTS:
                    conn_info['cert']['extensions'].update({
                        ext.oid._name: str(ext.value),
                    })
        if json:
            return json_dumps(conn_info, indent=4)
        return conn_info


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='host address')
    parser.add_argument('port', type=int, help='host service port')
    parser.add_argument('-j', '--json', action='store_true',
                        help='return JSON data')
    parser.add_argument('-z', '--no-validate', dest='validate',
                        action='store_false',
                        help='do not validate certificate')
    args = parser.parse_args()

    addr = (args.host, args.port)

    try:
        conn_info = get_sock_info(addr, json=args.json, validate=args.validate)
    except (ConnectionRefusedError, ssl.SSLError) as e:
        logging.error('Unable to establish SSL/TLS session: %s', e)
        parser.exit(1)
    except KeyboardInterrupt:
        parser.exit(1)

    if args.json:
        print(conn_info)
    else:
        fp = conn_info['cert'].pop('fingerprints')
        exts = conn_info['cert'].pop('extensions')
        print('Connection:')
        print(tabulate(conn_info['conn'].items(), tablefmt='plain'))
        print('\nCertificate:')
        print(tabulate(conn_info['cert'].items(), tablefmt='plain'))
        print('\nFingerprints:')
        print(tabulate(fp.items(), tablefmt='plain'))
        print('\nExtensions:')
        print(tabulate(exts.items(), tablefmt='plain'))
