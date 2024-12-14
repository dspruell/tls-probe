"""Probe SSL/TLS service to return connection and certificate details."""

import argparse
import logging
import socket
import ssl
from importlib.metadata import version
from json import dumps as json_dumps

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from jarm.scanner.scanner import Scanner
from tabulate import tabulate

__application_name__ = "tls-probe"
__version__ = version(__application_name__)


# Default socket (connection) timeout, in seconds
DEFAULT_SOCKET_TIMEOUT = 30
# Certificate extensions to render in output
RELEVANT_EXTS = [
    "subjectAltName",
]

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def convert_to_hexbytes(i, sep=None):
    """
    Convert an integer input to a hexadecimal string.

    Optionally separate converted bytes with a selected delimiter.
    """
    hexval = f"{i:x}"
    if sep:
        return sep.join(x + y for x, y in zip(hexval[::2], hexval[1::2]))
    else:
        return hexval


def get_jarm_fingerprint(addr, timeout=None):
    "Return JARM fingerprint for addr (a tuple of host and port)."
    kwargs = {}
    if timeout is not None:
        kwargs.update({"timeout": timeout})
    return Scanner.scan(*addr, **kwargs)


def get_sock_info(addr, timeout=None, json=False, validate=True):
    """
    Return SSL/TLS socket info for addr (a tuple of host and port).

    Negotiate socket while giving the option to drop strict certificate
    validation so that connections can be established and certificate data
    collected even in cases where verification fails.

    See also https://badssl.com/
    """
    context = ssl.create_default_context()
    context.check_hostname = True if validate else False
    context.verify_mode = ssl.CERT_REQUIRED if validate else ssl.CERT_NONE

    with socket.create_connection(addr, timeout=timeout) as sock:
        conn_info = dict(conn={}, cert={"fingerprints": {}, "extensions": {}})
        with context.wrap_socket(sock, server_hostname=addr[0]) as ssock:
            cert = ssock.getpeercert(binary_form=True)
            cert_data = x509.load_der_x509_certificate(cert, default_backend())
            jarm_data = get_jarm_fingerprint(addr, timeout=timeout)
            conn_info["conn"].update(
                {
                    "version": ssock.version(),
                    "remote_addr": ":".join(
                        [str(_) for _ in ssock.getpeername()]
                    ),
                    "jarm": jarm_data[0],
                }
            )
            conn_info["cert"].update(
                {
                    "issuer": cert_data.issuer.rfc4514_string(),
                    "subject": cert_data.subject.rfc4514_string(),
                    # The serial number is stored as an integer but should be
                    # output in standard colon separated hexadecimal format
                    "serial_int": cert_data.serial_number,
                    "serial": convert_to_hexbytes(
                        cert_data.serial_number, sep=":"
                    ),
                    "version": cert_data.version.name,
                    "signature_hash": cert_data.signature_hash_algorithm.name,
                    "not_valid_before": str(cert_data.not_valid_before_utc),
                    "not_valid_after": str(cert_data.not_valid_after_utc),
                }
            )
            conn_info["cert"]["fingerprints"].update(
                {
                    "md5": cert_data.fingerprint(hashes.MD5()).hex(),
                    "sha1": cert_data.fingerprint(hashes.SHA1()).hex(),
                    "sha256": cert_data.fingerprint(hashes.SHA256()).hex(),
                }
            )
            for ext in cert_data.extensions:
                if ext.oid._name in RELEVANT_EXTS:
                    conn_info["cert"]["extensions"].update(
                        {
                            ext.oid._name: str(ext.value),
                        }
                    )
        if json:
            return json_dumps(conn_info, indent=4)
        return conn_info


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="host address")
    parser.add_argument("port", type=int, help="host service port")
    parser.add_argument(
        "-j", "--json", action="store_true", help="return JSON data"
    )
    parser.add_argument(
        "-z",
        "--no-validate",
        dest="validate",
        action="store_false",
        help="do not validate certificate",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_SOCKET_TIMEOUT,
        help="set connection socket timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=__version__,
        help="print package version",
    )

    args = parser.parse_args()

    addr = (args.host, args.port)

    try:
        conn_info = get_sock_info(
            addr, timeout=args.timeout, json=args.json, validate=args.validate
        )
    except (TimeoutError, ConnectionRefusedError, ssl.SSLError) as e:
        logging.error("Unable to establish SSL/TLS session: %s", e)
        parser.exit(1)
    except KeyboardInterrupt:
        parser.exit(1)

    if args.json:
        print(conn_info)
    else:
        fp = conn_info["cert"].pop("fingerprints")
        exts = conn_info["cert"].pop("extensions")
        print("Connection:")
        print(tabulate(conn_info["conn"].items(), tablefmt="plain"))
        print("\nCertificate:")
        print(tabulate(conn_info["cert"].items(), tablefmt="plain"))
        print("\nFingerprints:")
        print(tabulate(fp.items(), tablefmt="plain"))
        print("\nExtensions:")
        print(tabulate(exts.items(), tablefmt="plain"))
