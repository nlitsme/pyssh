# Small SSH-2 client and server

Completed from the supplied `ssh.py` skeleton. The original reader/writer
helpers are included under their normal import names. Cryptographic primitives
come from `cryptography`; SSH negotiation, framing, key derivation,
authentication, channels, and connection state are implemented here.

## Requirements

Linux/POSIX, Python 3.10 or newer, and `cryptography` 47 or newer with an
ML-KEM-capable backend (current wheels include one):

```sh
python -m pip install -r requirements.txt
```

## Algorithms and behavior

| Component | Implemented |
| --- | --- |
| Preferred key exchange | `mlkem768x25519-sha256` |
| Compatibility key exchange | `curve25519-sha256`; force with `--curve25519` |
| Host keys and signatures | `ssh-ed25519` |
| Encryption/integrity | `chacha20-poly1305@openssh.com` |
| Compression | `none` |
| Authentication | Password and Ed25519 user public key |
| Sessions | One non-PTY shell or exec channel per TCP connection |
| Channel I/O | Binary stdin, stdout, stderr; EOF, exit status, window control |
| Rekeying | Either peer can initiate; automatic local byte/time thresholds |
| Host verification | Client requires an explicitly pinned Ed25519 `.pub` file |

PTY allocation, SFTP/subsystems, forwarding, SSH-1, host certificates,
other cryptographic algorithms, and multiple concurrent session channels are
not implemented. Unsupported requests are rejected rather than acknowledged
as successful. A plain shell is available through `ssh -T` or by omitting the
Python client's command; terminal editors and job control require a PTY.

The server's configured SSH username does **not** select or impersonate a Unix
account. Commands run as the OS user that started the server. The CLI serves
connections sequentially and binds to loopback by default. This is a compact
protocol implementation, not an OpenSSH replacement.

## Decode the supplied capture

```sh
python ssh.py decode tests/capture.txt
```

`>` denotes client-to-server, `<` server-to-client. TCP chunks may contain
partial packets or several packets. Each direction changes to opaque
ciphertext after its own `NEWKEYS`. The capture contains six plaintext SSH
packets, then 364 encrypted server bytes and 68 encrypted client bytes.
Those tails are retained exactly; the captured public values alone cannot
recover their session keys, decrypt them, or verify the server's KEX signature.

The decoder uses typed objects: `Hello`, `Msg20_KexInit`, `Msg21_NewKeys`,
`Msg30_ECDHInit`, `Msg31_ECDHReply`, `HostKey`, and `Signature`. Message numbers
30 and 31 have the same outer format for Curve25519 and the hybrid KEX.
`HybridInit` and `HybridReply` split the hybrid blobs into ML-KEM and X25519
components. Unknown messages retain their entire body in `RawPacket`;
`EncryptedData` explicitly denotes undecoded ciphertext. Decoded frames retain
all padding bytes and round-trip byte-for-byte.

## Password server and client

Generate a persistent host key and its public counterpart:

```sh
python ssh.py keygen host_ed25519
```

Start a server (the password prompt uses `getpass`):

```sh
python ssh.py server --host-key host_ed25519 --user testuser
```

In another terminal, use the matching public key obtained through a trusted
route:

```sh
python ssh.py client --host-key host_ed25519.pub --user testuser \
    127.0.0.1 'printf hello; printf error >&2; exit 7'
```

The client's process exit status is the remote command's exit status. Standard
input is forwarded, so this also works:

```sh
printf 'hello\n' | python ssh.py client --host-key host_ed25519.pub \
    --user testuser 127.0.0.1 cat
```

Options must precede the host name; everything after the host is the remote
shell command, matching the usual SSH convention. The default port is 2222;
use `--port 22` for an ordinary OpenSSH server.

Use `--password-env VARIABLE_NAME` to read credentials from an existing
environment variable instead of prompting. `--once` makes the server exit
after one connection. `--listen ADDRESS` changes its bind address.

An OpenSSH client can connect too:

```sh
ssh -T -p 2222 -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no testuser@127.0.0.1 'printf hello'
```

## Ed25519 user authentication

Generate a separate user key (or use an existing Ed25519 private key):

```sh
python ssh.py keygen user_ed25519
python ssh.py server --host-key host_ed25519 --user testuser \
    --authorized-key user_ed25519.pub
```

Connect with:

```sh
python ssh.py client --host-key host_ed25519.pub --identity user_ed25519 \
    --user testuser 127.0.0.1 'printf hello'
```

With `--authorized-key` alone, the server offers public-key authentication
only. Add `--password-env VARIABLE_NAME` to enable both methods. The Python
client can authenticate to an OpenSSH server when its user public key is
installed in that account's `authorized_keys`.

## Tests

The capture tests were written and run first, before implementing decoding.
They check independently recorded lengths, cookies, key/signature contents,
negotiation, packet boundaries, ciphertext tails, fragmentation, and exact
round trips. The remaining tests exercise framing, tampering, login failures,
host-key mismatches, full-duplex transfers larger than the channel window,
EOF, output streams, exit status, and both rekey directions.

```sh
python -m unittest discover -s tests -v
python -m unittest datareader datawriter -v
```

Validated here: **24 SSH tests plus 18 original helper tests**, all passing.
OpenSSH 10.0p2 independently verified both endpoints with both KEX methods;
rekeys during live transfers and after authentication were also tested.
OpenSSH-specific tests skip only when the relevant executable is absent.
The unprivileged `sshd -i` tests use temporary keys/configuration and the
current OS account; they do not modify its password or SSH configuration.

The new SSH code and tests pass Ruff's E/F/I checks at 79 columns; `ssh.py`
also passes mypy (`--follow-imports=silent`).

## Python API

```python
# written by chatgpt GPT-6
import socket
from pathlib import Path

from ssh import HostKey, SSHClient

pinned = HostKey.from_public_file(Path("host_ed25519.pub"))
with socket.create_connection(("127.0.0.1", 2222), timeout=30) as sock:
    client = SSHClient(sock, pinned)
    client.authenticate("testuser", "password")
    result = client.run("cat", input_data=b"binary\x00data\n")
    print(result.stdout, result.stderr, result.exit_status)
```

`run()` collects output in memory. `run_stream()` accepts binary input/output
streams for large transfers. Socket timeouts apply to incomplete reads, not
the total command duration. A `Connection`, and its channel/session objects,
are driven from one application thread; each connection has its own state.

## Protocol references

- [RFC 4251: data types](https://www.rfc-editor.org/rfc/rfc4251.html)
- [RFC 4252: user authentication](https://www.rfc-editor.org/rfc/rfc4252.html)
- [RFC 4253: transport and key derivation](https://www.rfc-editor.org/rfc/rfc4253.html)
- [RFC 4254: connection channels](https://www.rfc-editor.org/rfc/rfc4254.html)
- [RFC 8731: Curve25519](https://www.rfc-editor.org/rfc/rfc8731.html)
- [RFC 8709: Ed25519](https://www.rfc-editor.org/rfc/rfc8709.html)
- [OpenSSH ML-KEM/X25519 implementation](https://github.com/openssh/openssh-portable/blob/master/kexmlkem768x25519.c)
- [OpenSSH ChaCha20-Poly1305 construction](https://www.ietf.org/archive/id/draft-ietf-sshm-chacha20-poly1305-00.html)
