# BHTP/1 course project

Two standalone Python 3.9+ programs implement the binary protocol in [SPEC.md](SPEC.md). They use only the Python standard library and share no protocol code, so the spec is the contract between them.

Start the server in one terminal:

```sh
python bserve.py ./www 9000
```

Fetch the sample file in another:

```sh
python bcurl.py -v localhost:9000/index.html
```

On Windows, `py` may be used instead of `python`. On Unix, the scripts can also be made executable and run directly. `-v` writes a hexdump of each sent and received frame to stderr; the file body goes to stdout, so redirection remains safe:

```sh
python bcurl.py localhost:9000/index.html > downloaded.html
```

The server stays open for more requests on the same TCP connection. A missing file returns `404` and a malformed request returns `400`. The client exits with code `0` for a 2xx response, `1` for a non-2xx response, and `2` for a target, connection, or protocol error. By default the server listens only on `127.0.0.1`; use `--host` to choose another IPv4 or IPv6 address. Both programs accept `--timeout SECONDS` (default: 30).

Run the integration tests with:

```sh
python -m unittest discover -s tests -v
```
