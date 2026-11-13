# KNSH-004 — Frame codec and binary streams

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Wire protocol | L (5) | [KNSH-003](KNSH-003-strict-json-reader-and-writer.md) | `knsh-json` | NFR-SEC-07, [wire format](../06-api/wire-format.md#frames-unix-sockets) |

**Description.** As a client or the engine, I want to read and write length-prefixed frames with JSON messages and
binary streams, so that raw bytes travel beside JSON without base64 overhead and oversized frames are refused
before allocation. Works on any `Read`/`Write`. Out of scope: XPC transport.

**Acceptance criteria**
- [ ] Frame layout: 4-byte big-endian length (type + stream ID + payload), 1-byte type (`0x01` JSON, `0x02` binary
      chunk, `0x03` end of stream), 4-byte stream ID, payload ≤ 1 MB.
- [ ] The reader reads the length first and returns a fatal error (connection must close) for any frame over the
      limit, before allocating memory for the payload.
- [ ] JSON frames must use stream ID 0; binary chunks must name a stream opened by a prior JSON message; a chunk
      for an unknown or closed stream is a fatal error.
- [ ] Unknown frame types are a fatal error.
- [ ] A stream demultiplexer delivers chunks per stream ID and signals end of stream; streams can interleave.
- [ ] A base64 fallback helper exists for clients that declared in `hello` that they cannot handle binary frames.
- [ ] Short reads and partial frames are handled; EOF mid-frame is an error, not a truncated message.

**Unit tests**
- `rejects_oversized_frame_before_allocating` — NFR-SEC-07 (uses a reader that fails if more than the header is
  requested).
- `json_frame_requires_stream_zero` — layout rule.
- `binary_chunk_for_unknown_stream_is_fatal` — stream rule.
- `interleaved_streams_are_demultiplexed` — multiplexing.
- `eof_mid_frame_is_error` — partial input.
- `round_trips_json_and_binary_frames` — codec.
