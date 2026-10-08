# BHTP/1: Binary HTTP for static files

This is the wire specification for two independent programs: `bserve.py` serves a directory and `bcurl.py` fetches one path. BHTP/1 runs directly over TCP. One connection carries any number of frames, in order. The server answers each valid request frame on that same connection. There is no HTTP text syntax, compression, encryption, multiplexing, request body, or redirect handling in version 1. Numeric fields are unsigned and in network byte order (big endian).

## Frame

Every frame starts with this **16-byte fixed header**:

| Offset | Width | Field | Version 1 rule |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `BHTP` (`42 48 54 50`) |
| 4 | 1 | version | `1` |
| 5 | 1 | type | `1` request, `2` response |
| 6 | 1 | flags | `0` |
| 7 | 1 | reserved | `0` |
| 8 | 4 | request ID | Nonzero on a request; response echoes it |
| 12 | 4 | payload length | Number of bytes after this header, at most 16,777,216 |

The length includes the complete type-specific payload, so the next frame begins exactly 16 + payload length bytes after this one. The receiver **MUST consume and skip the entire payload of a valid frame whose type it does not know**, then continue with the next frame on the same TCP connection. This rule applies to either endpoint and is what permits new frame types in a later version. A receiver may discard unknown payloads in chunks instead of allocating them.

The 16-byte choice keeps framing simple: four bytes each for a recognizable magic, request identity, and payload length, plus four one-byte control fields. HTTP/2's 24-bit length, 8-bit type, 8-bit flags, and 31-bit stream ID support multiplexed streams; BHTP/1 has only ordered requests, so it uses ordinary 32-bit integers and no stream state. The 16 MiB limit bounds memory and prevents a peer from declaring an unreasonably large frame.

## Request and response payloads

A type `1` request payload is `path_length:u16`, exactly that many UTF-8 path bytes, `header_count:u8`, then that many header entries. The path is 1–4096 bytes, begins with `/`, and has no control characters, backslash, `?`, or `#`. It is a literal path: percent escapes are **not** decoded. `/` and a path ending in `/` select `index.html` in that directory. The server resolves the result under its chosen root; a path that escapes that root is a `400` error. There is no request body.

A type `2` response payload is `status:u16`, `header_count:u8`, that many header entries, then all remaining bytes as the body. Status is in 100–599. The server emits `200` for a file, `404` for a missing file, `400` for a bad request or unsafe path, and `500` for a file read or size failure. The client writes body bytes unchanged to stdout and exits nonzero for a non-2xx status. `content-length` is required in every response and equals the body byte count; the frame payload length is still authoritative for finding the next frame.

Each header entry is `name_id:u8`, `value_length:u16`, then exactly that many UTF-8 value bytes. Values are at most 1024 bytes and cannot contain CR, LF, or NUL. A receiver ignores an unrecognized name ID using its value length, and rejects duplicate recognized names. No name strings are sent on the wire. These are the **ten names the programs actually send**, numbered once for both directions:

| ID | Name | Sent by |
| ---: | --- | --- |
| 1 | `host` | client |
| 2 | `user-agent` | client |
| 3 | `accept` | client |
| 4 | `accept-encoding` | client (`identity`) |
| 5 | `connection` | both |
| 6 | `content-type` | server |
| 7 | `content-length` | server |
| 8 | `server` | server |
| 9 | `cache-control` | server (`no-store`) |
| 10 | `accept-ranges` | server (`none`) |

Known request payload errors get a `400` response and the server remains ready for the next frame. Invalid magic, version, flags, reserved byte, or an oversized payload means framing cannot be trusted: the server sends `400` if it can and closes. A truncated frame or idle timeout closes the connection. The client sends one request on one TCP connection, reads frames until its matching response, and never retries on another connection. Its `-v` option sends a hexdump of every frame to stderr; stdout remains only the response body.

## Annotated complete exchange

This exchange fetches `/index.html` from `localhost:9000` with request ID 1. The file contains exactly `<!doctype html><title>BHTP</title><h1>Hello, binary HTTP!</h1>\n` (63 bytes). Offsets are hexadecimal. The left column is the byte offset of the first byte on that row; all bytes are shown, including the final newline (`0a`).

**Request, 87 bytes (16-byte header + 71-byte payload):**

```text
0000: 42 48 54 50 01 01 00 00 00 00 00 01 00 00 00 47
0010: 00 0b 2f 69 6e 64 65 78 2e 68 74 6d 6c 05 01 00
0020: 0e 6c 6f 63 61 6c 68 6f 73 74 3a 39 30 30 30 02
0030: 00 07 62 63 75 72 6c 2f 31 03 00 03 2a 2f 2a 04
0040: 00 08 69 64 65 6e 74 69 74 79 05 00 0a 6b 65 65
0050: 70 2d 61 6c 69 76 65
```

Bytes `00–03` are `BHTP`; `04=01` is version; `05=01` is request type; `06–07=00` are flags/reserved; `08–0b=00000001` is the request ID; `0c–0f=00000047` is 71 payload bytes. At `10`, `000b` says the next 11 bytes are `/index.html`; `1d=05` says five headers follow. Their IDs and lengths are `01/000e` (`host`, `localhost:9000`), `02/0007` (`user-agent`, `bcurl/1`), `03/0003` (`accept`, `*/*`), `04/0008` (`accept-encoding`, `identity`), and `05/000a` (`connection`, `keep-alive`).

**Response, 141 bytes (16-byte header + 125-byte payload):**

```text
0000: 42 48 54 50 01 02 00 00 00 00 00 01 00 00 00 7d
0010: 00 c8 06 05 00 0a 6b 65 65 70 2d 61 6c 69 76 65
0020: 06 00 09 74 65 78 74 2f 68 74 6d 6c 07 00 02 36
0030: 33 08 00 08 62 73 65 72 76 65 2f 31 09 00 08 6e
0040: 6f 2d 73 74 6f 72 65 0a 00 04 6e 6f 6e 65 3c 21
0050: 64 6f 63 74 79 70 65 20 68 74 6d 6c 3e 3c 74 69
0060: 74 6c 65 3e 42 48 54 50 3c 2f 74 69 74 6c 65 3e
0070: 3c 68 31 3e 48 65 6c 6c 6f 2c 20 62 69 6e 61 72
0080: 79 20 48 54 54 50 21 3c 2f 68 31 3e 0a
```

The header repeats request ID 1, changes type to `02`, and declares `0000007d` (125) payload bytes. At `10`, `00c8` is status 200 and `12=06` announces six headers. They are `05/000a` (`keep-alive`), `06/0009` (`text/html`), `07/0002` (`63` body bytes), `08/0008` (`bserve/1`), `09/0008` (`no-store`), and `0a/0004` (`none`). The body begins at offset `4e` with `<` (`3c`) and ends at `8c` with newline (`0a`). Its 63 bytes plus 62 bytes of status and headers account for all 125 payload bytes.
