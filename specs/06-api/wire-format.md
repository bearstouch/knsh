# Wire format

Messages are JSON; raw bytes travel in binary frames beside them. JSON keeps the API readable, debuggable and easy to evolve, and its cost (microseconds per message) is negligible next to starting a sandboxed process.

## Frames (Unix sockets)

| Frame part | Size | Content |
| --- | --- | --- |
| Length | 4 bytes, big-endian | Size of type + stream ID + payload |
| Type | 1 byte | `0x01` JSON message, `0x02` binary chunk, `0x03` end of stream |
| Stream ID | 4 bytes | 0 for JSON messages; for binary chunks, the stream named in the JSON that opened it |
| Payload | Up to 1 MB | UTF-8 JSON, or raw bytes |

- The receiver reads the length first and closes the connection on any frame over the limit, before allocating memory for it.
- Any other framing violation also closes the connection, and nothing after it is read: a length smaller than the type and stream ID, an unknown type, a JSON message on a stream other than 0, a binary chunk or end-of-stream frame on stream 0 or on a stream that is not open (never opened, or already ended), an end-of-stream frame with a payload, a stream that carries more or fewer bytes than the size its opening message declared, more than 256 streams open at once, and input that ends inside a frame or while a stream is still open. A JSON message that is well framed but not strict JSON is answered with a parse error (`-32700`, `id: null`), and then the connection is closed: the engine never recovers from malformed input, and nothing after it is read (KNSH-013).
- Stream 0 is reserved for JSON messages, so a stream ID is never 0. An ID may be reused once its stream has ended.
- **Raw bytes** (command output through `records.output` and `command.output`, file contents in `checkpoint.diff`) go in binary chunks. A JSON message opens the stream with its ID, size and content type, and an end-of-stream frame closes it.
- A client that cannot handle binary frames says so in `hello` and receives the bytes base64-encoded inside JSON instead: the standard alphabet with padding (RFC 4648 section 4), and only the canonical encoding is accepted (no whitespace, no URL-safe alphabet, unused bits zero).
- Output from `knsh -c` never crosses the API: the client hands its stdio descriptors to the supervisor, which attaches them to the command directly.

## Descriptors

Descriptors travel as `SCM_RIGHTS` ancillary data on the Unix socket (KNSH-049):

- The sender sends a request's whole frame with the descriptors attached to its first byte. The receiver reads exactly
  one frame at a time, so the descriptors received while a frame is read belong to that frame.
- Only `exec.run` with `stdio: "passed"` takes descriptors: exactly three, stdin, stdout and stderr in that order. A
  request for any other method that carries descriptors is answered `-32602`; descriptors on a notification or
  response are closed unused; and whatever a handler does not take is closed when the call ends.
- At most three may arrive with one frame. More, truncated ancillary data, or ancillary data other than `SCM_RIGHTS`
  close the connection, and every descriptor that did arrive is closed.
- Received descriptors are made close-on-exec at once. macOS has no `MSG_CMSG_CLOEXEC`, so a process spawned by another
  `knshd` thread in the instant between receiving and marking could inherit one; the only such children are the
  engine's own.

## Control service (XPC)

The control service carries the same JSON payload inside XPC messages, and raw bytes as XPC data values, so all three endpoints share one schema.

- **Shape.** Each message is an XPC dictionary. Key `json` holds one JSON-RPC message (UTF-8, strict profile below)
  as an XPC data value, at most 1 MB, the frame payload limit. Messages from `knshd` may also hold key `bytes`: the
  raw bytes of the stream the JSON names (for example `records.output`), in place of binary chunks. A request must
  hold exactly the key `json`; anything else (a missing or non-data `json`, a larger payload, `bytes` or any other
  key) closes the connection without an answer, like a framing violation on a socket.
- **Answers** go back as the XPC reply to the request (or as a plain message if the request expects no reply). Event
  notifications are plain messages on the same connection, sent after the answer that created the subscription. A
  client that receives replies and messages on different queues must order them itself (by subscription ID). A
  closing error answer (`-32600`, `-32700`) is sent just before the connection is cancelled and may not arrive.
- **Same rules.** Handshake first, `-32700` closes, the same dispatch rules; only the method list differs per
  endpoint. No descriptors travel over XPC.
- **Verification first** ([control service](control-service.md#verification)). Every message's sender is checked
  before the message is read; a refused sender's connection is closed without an answer (KNSH-067).

## Strict JSON profile

The engine accepts only a strict subset of JSON, based on I-JSON (RFC 7493), because its JSON parser reads input from untrusted processes:

- Valid UTF-8 only; no unpaired surrogate escapes.
- No duplicate keys in an object. Two parsers that disagree on which duplicate wins are a classic security bug.
- Integers within ±2^53; larger values, such as byte counts that might exceed it, are sent as strings.
- At most 32 levels of nesting.
- Anything that does not conform is rejected with a JSON-RPC parse error (`-32700`), and the engine never attempts recovery.
- Everything the engine sends conforms to the same profile.
