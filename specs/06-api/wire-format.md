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

## Control service (XPC)

The control service carries the same JSON payload inside XPC messages, and raw bytes as XPC data values, so all three endpoints share one schema.

## Strict JSON profile

The engine accepts only a strict subset of JSON, based on I-JSON (RFC 7493), because its JSON parser reads input from untrusted processes:

- Valid UTF-8 only; no unpaired surrogate escapes.
- No duplicate keys in an object. Two parsers that disagree on which duplicate wins are a classic security bug.
- Integers within ±2^53; larger values, such as byte counts that might exceed it, are sent as strings.
- At most 32 levels of nesting.
- Anything that does not conform is rejected with a JSON-RPC parse error (`-32700`), and the engine never attempts recovery.
- Everything the engine sends conforms to the same profile.
