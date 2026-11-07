# Small SSH-2 client and server

Completed from the supplied `ssh.py` skeleton. The original reader/writer
helpers are included under their normal import names. Cryptographic primitives
come from `cryptography`; SSH negotiation, framing, key derivation,
authentication, channels, and connection state are implemented here.

The purpose of this python implementation is to get a overview of all messages
and operations involved in the ssh protocol.


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
| Sessions | One shell, exec, PTY, or SFTP channel per TCP connection |
| PTY | Controlling terminal, terminal modes, dimensions, window changes, merged stdout/stderr |
| Environment | `TERM`, `COLORTERM`, `LANG`, and `LC_*` before process start |
| SFTP | System OpenSSH `sftp-server`; typed version-3 protocol tracing |
| Channel I/O | Binary stdin, stdout, stderr; EOF, exit status, window control |
| Rekeying | Either peer can initiate; automatic local byte/time thresholds |
| Host verification | Optional Ed25519 `.pub` pin; otherwise accept the presented key and warn |

Forwarding, SSH-1, host certificates, other cryptographic algorithms,
unconfigured subsystems, and multiple concurrent session channels are not
implemented. Unsupported requests are rejected. A plain shell is available
through `ssh -T` or by omitting the Python client's command; request a PTY
for terminal editors and job control.

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

## Wire-object interface

Every message and nested wire structure has the same instance methods:

```python
# written by chatgpt GPT-6
from ssh import Msg5_ServiceRequest, SSHReader, SSHWriter

packet = Msg5_ServiceRequest("ssh-userauth")
writer = SSHWriter()
packet.encode(writer)  # Message body fields, excluding the message-type byte.

copy = Msg5_ServiceRequest()
reader = SSHReader(writer.getvalue())
copy.decode(reader)  # Populate this instance; returns None, like encode().
reader.finish()
```

`SSHReader` and `SSHWriter` extend your `DataReader`/`DataWriter` classes.
They retain `read32be`/`write32be` and add `readldata`/`writeldata`,
`readlstr`/`writelstr`, `readboolean`/`writeboolean`, and
`readmpint`/`writempint`. SSH strings retain
NULs; malformed text is rejected rather than silently discarded.

`encode_message` writes the message-type byte followed by `packet.encode`.
`decode_message` reads the type, creates the declared message class, and calls
its instance `decode`. `SSH2Frame` owns the packet length, padding length,
message envelope, and padding. Its encode/decode methods follow that order
explicitly. `encode_object` and `decode_object` are convenience functions for
an entire isolated object; they do not replace its reader/writer interface.
`decode_object` also checks that no trailing bytes were left unconsumed.

There are 29 declared message types. Authentication-method fields live in
`NoneAuth`, `PasswordAuth`, `PublicKeyAuth`, or `UnknownAuth`. Channel request
fields live in `ShellRequest`, `ExecRequest`, `SignalRequest`,
`ExitStatusRequest`, `ExitSignalRequest`, `PtyRequest`, `EnvRequest`,
`SubsystemRequest`, `WindowChangeRequest`, or `OpaqueRequest`.
All use the same instance encode/decode interface. Unknown messages retain
their complete body in `RawPacket`; unsupported method/request payloads remain
explicitly opaque. `EncryptedData` denotes undecoded ciphertext.

Global requests use `HostKeysRequestData` for OpenSSH's
`hostkeys-00@openssh.com` and `hostkeys-prove-00@openssh.com` key lists;
other bodies use `OpaqueGlobalRequestData`. Each `AdvertisedHostKey`
decodes RSA, ECDSA, or Ed25519 parameters. Unknown key types retain their
remaining bytes in `OpaquePublicKeyFields.undecoded`. This decodes the
advertisements; it does not implement automatic host-key learning or proof
responses, or change the algorithms accepted for authentication.

`PtyRequest` decodes the terminal name, character/pixel dimensions, and the
length-prefixed terminal modes. `TerminalModes` retains the ordered
`TerminalMode` entries, including duplicates and the terminating opcode.
Modes 1..159 carry a uint32 argument; unknown mode numbers retain that value.
Opcode zero ends the list, and opcodes 160..255 stop further parsing.
Any bytes after a stop opcode remain explicit in `undecoded` and round-trip
unchanged. Empty mode strings are accepted; truncated arguments and nonempty
lists without a stop opcode are rejected.

Terminal names and `EnvRequest` variable/value strings retain their original
bytes, including values that are not UTF-8. Tracing renders pure UTF-8 text
as a quoted field and binary data as full hex. The server applies supported
terminal modes and accepted environment requests before starting a process.

SFTP has 27 declared message classes covering the version-3 messages,
plus `SftpAttributes`, `SftpName`, `SftpExtension`, and `SftpFrame`, all with
the same instance encode/decode interface. `SftpStream` assembles length-prefixed
packets across SSH channel messages, including multiple packets in one message.
Unknown types, malformed bodies, later protocol versions, and extension-specific
bodies remain explicitly undecoded and preserve their original bytes.

`HostKey`, `Signature`, `Hello`, `HybridInit`, and `HybridReply` also use this
interface. Message types 30/31 have the same outer format for Curve25519 and
hybrid KEX; the hybrid structures split the ML-KEM and X25519 components.
Captured frames retain all padding bytes and round-trip byte-for-byte.

## Password server and client

Generate a persistent host key and its public counterpart:

```sh
python ssh.py keygen host_ed25519
```

Start a server (the password prompt uses `getpass`):

```sh
python ssh.py server -k host_ed25519 -u testuser
```

In another terminal, connect without a pin (this emits the unverified-key warning):

```sh
python ssh.py client -u testuser \
    127.0.0.1 'printf hello; printf error >&2; exit 7'
```

The client's process exit status is the remote command's exit status. Standard
input is forwarded, so this also works:

```sh
printf 'hello\n' | python ssh.py client --host-key host_ed25519.pub \
    --user testuser 127.0.0.1 cat
```

Options must precede the host name; everything after the host is the remote
shell command, matching the usual SSH convention. The default port is 22.
Use `-p 2222` on both endpoints to choose another port.

Password lookup is `--password/-P` first, then the fixed `SSH_PASSWORD`
environment variable, then a `getpass` prompt. No environment-variable name
argument is needed. `--once/-o` exits after one connection and `--listen/-l`
changes the server's bind address.

A client host key is optional. With no `--host-key/-k`, the client accepts the
presented key and emits a warning containing its SHA-256 fingerprint. It still
verifies the key-exchange signature. Supplying a pin requires an exact match;
a mismatch fails before user authentication.

| Option | Short form | Default/meaning |
| --- | --- | --- |
| `--verbose` | `-v` / `-vv` | Full message hex / decoded fields, to stderr |
| `--port` | `-p` | 22 |
| `--user` | `-u` | Required SSH username |
| `--password` | `-P` | Otherwise `SSH_PASSWORD`, then prompt |
| `--host-key` | `-k` | Required private key for server; optional public pin for client |
| `--identity` | `-i` | Client user private key |
| `--authorized-key` | `-a` | Server's accepted user public key |
| `--listen` | `-l` | Server bind address, default `127.0.0.1` |
| `--once` | `-o` | Serve one connection |
| `--curve25519` | `-c` | Disable hybrid ML-KEM |
| `--timeout` | `-t` | Incomplete network-read timeout, default 30 seconds |
| `--pty` | `-T` | Client: allocate a PTY and use local terminal raw mode |
| `--subsystem` | `-s` | Client: run a subsystem instead of a shell/command |
| `--sftp-server` | `-s` | Server: path to the OpenSSH SFTP executable; otherwise autodetect |

An OpenSSH client can connect too:

```sh
ssh -T -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no testuser@127.0.0.1 'printf hello'
```

## PTY and SFTP sessions

Request a PTY using this Python client or OpenSSH:

```sh
python ssh.py client -T -u testuser 127.0.0.1
ssh -tt testuser@127.0.0.1
```

In this script, `-T` means `--pty`; the existing `-t` remains `--timeout`.
OpenSSH uses different flags: `-t`/`-tt` requests a PTY and `-T` disables it.
The Python CLI restores the local terminal on exit, including exceptions,
and forwards window changes while running in the main thread. The child
gets a controlling terminal; terminal output, including stderr, shares the
PTY's stdout stream. In canonical mode, SSH EOF is translated to the configured
VEOF character. A raw PTY has no input half-close operation, so its program
must exit through its protocol, terminal input, a signal, or channel close.

The server accepts `TERM`, `COLORTERM`, `LANG`, and names starting with `LC_`
before starting the child. Invalid names, NUL bytes, other variables, and
changes after process start are rejected. `SessionConfig.allowed_environment`
can extend the accepted exact names for API users.

SFTP uses the installed OpenSSH `sftp-server`, autodetected at common Linux
and BSD paths or on `PATH`. No `sshd` process is involved. If it is installed
elsewhere, configure its executable explicitly:

```sh
python ssh.py server -k host_ed25519 -u testuser -s /usr/lib/ssh/sftp-server
sftp testuser@127.0.0.1
```

The SFTP helper runs as the OS user that started this server, with that user's
filesystem permissions. There is no additional filesystem sandbox or account
switch. A missing helper or unknown subsystem causes channel-request failure;
success is sent only after spawning the configured process. Combining SFTP
with a PTY is rejected to preserve the binary protocol.

The Python client can carry a subsystem's binary protocol on stdin/stdout:

```sh
python ssh.py client -s sftp -u testuser 127.0.0.1
```

This is a protocol stream, not an interactive SFTP command interpreter.
Use OpenSSH's `sftp` for commands such as `put`, `get`, and `ls`. A subsystem
client must read responses while keeping its input open; closing stdin can
make the helper exit before queued responses are delivered.

## Protocol tracing

Use `-v` or `--verbose` on either endpoint for a complete single-line hex
record for every sent and received SSH message:

```sh
python ssh.py client -v -u testuser 127.0.0.1 'uname -a'
python ssh.py server -v -k host_ed25519 -u testuser
```

For example:

```text
20:12:34.123456 send SSH_MSG_SERVICE_REQUEST 050000000c7373682d7573657261757468
```

The hex is the message-type byte followed by the entire body. It is not
truncated or wrapped, and excludes transport length fields, padding, and
authentication tags. Outgoing messages are logged before encryption;
incoming messages after decryption, integrity verification, and decoding.
Identification/pre-banner lines are also logged, with their complete bytes.
Direction is relative to the endpoint producing the log.
Every record starts with local time in `HH:MM:SS.uuuuuu` format, including
identification records. The six fractional digits represent microseconds.

Use `-vv` (or repeat `--verbose`) for the decoded representation instead:

```text
20:12:34.123456 send SSH_MSG_SERVICE_REQUEST (type=5, 17 bytes)
  service: 'ssh-userauth'
```

Nested authentication and request structures retain named fields. Algorithm
lists are shown one entry per line. Pure UTF-8 text appears once, for example
`variable: 'COLORTERM'` and `value: 'truecolor'`. Quotes, backslashes, tabs,
and newlines are escaped so the representation stays lossless. Other binary
values include lengths and full offset-labelled hex dumps. Hybrid key-exchange messages are named according to the
negotiated algorithm. `-vvv` and higher use the same decoded format as `-vv`.
The timestamp appears once on the message header; decoded fields remain
grouped underneath. Host-key advertisements include SHA-256 fingerprints,
key sizes, RSA exponents and moduli, ECDSA curves and point coordinates,
and Ed25519 public bytes. Unknown parameters remain explicitly undecoded.
PTY requests show terminal dimensions and named modes such as `VINTR`,
`ICANON`, `ECHO`, `IUTF8`, and input/output speeds. Control-character modes
also show caret notation or `disabled`. Environment requests show the
variable name and value as separate fields.

After observing a request for the `sftp` subsystem, `-vv` decodes channel data
as SFTP frames. The nine bytes `00 00 00 05 01 00 00 00 03` become
`SSH_FXP_INIT (type=1, length=5)` with `version: 3`. Each direction has its
own assembly buffer. Incomplete packets retain explicit raw bytes until a
complete frame arrives; unfinished data is reported at channel EOF/close.
The log marks whether the subsystem request was accepted or rejected, so
inspection of traffic after a failed request does not imply a valid session.
`-v` continues to show the exact SSH message hex without reformatting it.

Tracing goes to stderr, leaving command stdout unchanged. This is a full
plaintext trace: passwords and channel contents are included. The default
verbosity is zero. Library users can pass `verbose=1` or `verbose=2`, and an
optional text `trace_stream`, to `SSHClient`, `SSHServer`, or `Connection`.

## Ed25519 user authentication

Generate a separate user key (or use an existing Ed25519 private key):

```sh
python ssh.py keygen user_ed25519
python ssh.py server -k host_ed25519 -u testuser \
    --authorized-key user_ed25519.pub
```

Connect with:

```sh
python ssh.py client --host-key host_ed25519.pub --identity user_ed25519 \
    --user testuser 127.0.0.1 'printf hello'
```

With `--authorized-key` alone, the server offers public-key authentication
only. Add `--password/-P` or set `SSH_PASSWORD` to enable both methods. The Python
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

The additional host-key capture tests check all three advertised keys,
exact round trips, malformed inputs, and fingerprints against `ssh-keygen`.
Trace tests cover microsecond timestamp formatting at both verbosity levels.
The PTY/environment captures check dimensions, mode parameters, environment
strings, and exact round trips. Additional tests cover unknown modes,
stop opcodes, retained undecoded tails, duplicate modes, binary strings,
every truncated capture prefix, and PTY/environment request handling.
SFTP tests cover the supplied subsystem and INIT captures, all 27 message
interfaces, attributes, fragmentation/coalescing, invalid input, and opaque
extension bodies. Live tests cover controlling-terminal access, terminal
modes, canonical EOF, a 3 MiB raw PTY transfer, running-process resize signals,
local terminal restoration, and OpenSSH SFTP upload/download/list/rename/
symlink/removal operations in temporary directories.

Validated here: **79 SSH tests (78 passed, one environment skip) plus
18 original helper tests**, all checks passing. The skipped test is the
Python PTY client against an unprivileged `sshd`: this container prevents
`sshd` from changing `/dev/pts` ownership. The Python PTY client/server and
OpenSSH client against this script's PTY server are independently tested.
OpenSSH 10.0p2 independently verified both endpoints with both KEX methods;
rekeys during live transfers and after authentication were also tested.
OpenSSH-specific tests skip when an executable is absent or the documented
unprivileged PTY limitation is encountered.
The unprivileged `sshd -i` tests use temporary keys/configuration and the
current OS account; they do not modify its password or SSH configuration.

The new SSH code and tests pass Ruff's E/F/I checks with a 160-column limit; `ssh.py`
also passes mypy (`--follow-imports=silent`).

## Python API

```python
# written by chatgpt GPT-6
import socket
from pathlib import Path

from ssh import HostKey, SSHClient

pinned = HostKey.from_public_file(Path("host_ed25519.pub"))
with socket.create_connection(("127.0.0.1", 22), timeout=30) as sock:
    client = SSHClient(sock, pinned)
    client.authenticate("testuser", "password")
    result = client.run("cat", input_data=b"binary\x00data\n")
    print(result.stdout, result.stderr, result.exit_status)
```

`run()` collects output in memory. `run_stream()` accepts binary input/output
streams for large transfers. Socket timeouts apply to incomplete reads, not
the total command duration. A `Connection`, and its channel/session objects,
are driven from one application thread; each connection has its own state.
Pass `terminal=PtyRequest(...)` to `run`/`run_stream` to request a PTY.
`run_subsystem(name, source, stdout, stderr)` forwards a binary subsystem
stream. The caller supplies its application protocol and coordinates requests
and replies. `SSHServer(..., session_config=SessionConfig(...))` selects the
SFTP executable and accepted exact environment names.

## Protocol references

- [RFC 4251: data types](https://www.rfc-editor.org/rfc/rfc4251.html)
- [RFC 4252: user authentication](https://www.rfc-editor.org/rfc/rfc4252.html)
- [RFC 4253: transport and key derivation](https://www.rfc-editor.org/rfc/rfc4253.html)
- [RFC 4254: connection channels](https://www.rfc-editor.org/rfc/rfc4254.html)
- [RFC 8160: IUTF8 terminal mode](https://www.rfc-editor.org/rfc/rfc8160.html)
- [RFC 8731: Curve25519](https://www.rfc-editor.org/rfc/rfc8731.html)
- [RFC 8709: Ed25519](https://www.rfc-editor.org/rfc/rfc8709.html)
- [SFTP version 3](https://www.ietf.org/archive/id/draft-ietf-secsh-filexfer-02.txt)
- [OpenSSH sftp-server](https://man.openbsd.org/sftp-server)
- [OpenSSH ML-KEM/X25519 implementation](https://github.com/openssh/openssh-portable/blob/master/kexmlkem768x25519.c)
- [OpenSSH ChaCha20-Poly1305 construction](https://www.ietf.org/archive/id/draft-ietf-sshm-chacha20-poly1305-00.html)
