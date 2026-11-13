# Events

Events tell subscribers what happened; hooks ([hooks.md](hooks.md)) help decide what may happen. Every event is observe-only. The envelope format and catalog are in [../05-models/event.md](../05-models/event.md).

| ID | Requirement |
| --- | --- |
| FR-EVT-01 | The event bus must fan every event out to all subscribers allowed to see it: on `agent.sock`, only the caller's session; on `user.sock` and the control service, all sessions. |
| FR-EVT-02 | `seq` must increase per session. |
| FR-EVT-03 | The engine must keep a buffer of the last 10,000 events per session, and subscribers must be able to resume with `events.subscribe {since_seq}`. |
| FR-EVT-04 | Delivery beyond the buffer is at most once. Anything needed later must be available in the record store. |
| FR-EVT-05 | No event except `command.proposed` (through hooks) and `decision.requested` (through the authority) may influence a decision. |
| FR-EVT-06 | `decision.requested` must be sent to the authority only. |
| FR-EVT-07 | Redaction must run before anything is emitted. |
| FR-EVT-08 | `file.changed` must be emitted for a change under a checkpoint root by any process, not only agents. |
