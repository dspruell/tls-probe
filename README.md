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

JSON data may optionally be returned.

By default, the tool validates certificates sent by the remote service and
certificate validation errors are raised. This may be changed by using the
`-z/--no-validate` option.

Full usage details are found in the `--help/-h` output to the command line
utility.

