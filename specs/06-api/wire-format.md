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
- **Raw bytes** (command output through `records.output` and `command.output`, file contents in `checkpoint.diff`) go in binary chunks. A JSON message opens the stream with its ID, size and content type, and an end-of-stream frame closes it.
- A client that cannot handle binary frames says so in `hello` and receives the bytes base64-encoded inside JSON instead.
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
