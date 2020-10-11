# tls-probe
Simple utility to probe remote SSL/TLS service.

Module opens connection to specified host and port and returns information
about the established socket and certificate served to client on that
connection.

Also provides command line frontend (`tls-probe`) to dump information in
human-readable format.

## Installation

Install from [PyPI](https://test.pypi.org/project/tls-probe/).
Use Python 3 and a virtualenv. 

```
mkdir -p ~/venv.d
python3 -mvenv ~/venv.d/tls_probe
~/venv.d/tls_probe/bin/pip install tls-probe
```

## Usage
Given an address (hostname or IP address) and port, a connection to the
specified service is made, a SSL/TLS socket is established, and details are
returned to the caller. This includes information about the connection as well
as some details from the x.509 certificate, if one is served.

For example:

```
$ tls-probe www.letsencrypt.org 443
Connection:
version      TLSv1.3
remote_addr  162.243.166.170:443

Certificate:
issuer            CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
subject           CN=lencr.org
serial            331089264146011497466023867100015958696279
version           v3
signature_hash    sha256
not_valid_before  2020-09-03 23:37:34
not_valid_after   2020-12-02 23:37:34

Fingerprints:
md5     a2572461046c4494e73d53d8a27ebc37
sha1    0b4843d5542903b7d7dfda1e7999e880a957087b
sha256  923455ed89054c81c6ff9d75c4185bb286ef94ea35ab1f08aeec136ad53388a2

Extensions:
subjectAltName  <SubjectAlternativeName(<GeneralNames([<DNSName(value='lencr.org')>, <DNSName(value='letsencrypt.org')>, <DNSName(value='www.lencr.org')>, <DNSName(value='www.letsencrypt.org')>])>)>
```

JSON data may optionally be returned.

By default, the tool validates certificates sent by the remote service and
certificate validation errors are raised. This may be changed by using the
`-z/--no-validate` option.

Full usage details are found in the `--help/-h` output to the command line
utility.
