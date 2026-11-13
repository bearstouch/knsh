# KNSH-018 — Event bus and subscriptions

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Events / API | XL (8) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | `knsh-core`, `knshd`, `knsh-proto` | FR-EVT-01 – FR-EVT-04, FR-EVT-07, [event](../05-models/event.md), FR-EVT-03, [user socket](../06-api/user-socket.md) |

**Description.** Merged from *Event bus* and *`events.subscribe` and `events.unsubscribe`*: they are done and validated together because the bus is validated through `events.subscribe` with `since_seq`.

*Event bus.* As a subscriber, I want ordered events per session with a resumable buffer, so that I can follow
what happens and catch up after a disconnect. Envelope fields: `event`, `id`, `seq`, `ts`, `session_id`, `actor`,
`data`.

*`events.subscribe` and `events.unsubscribe`.* As an observer, I want to subscribe to events over `user.sock`, optionally from `since_seq`, so that
clients can watch live and resume after reconnecting.

**Acceptance criteria**
*Event bus*

- [x] `seq` increases by one per session with no gaps.
- [x] The last 10,000 events per session are buffered; older ones are dropped.
- [x] Publishing never blocks on a slow subscriber; a subscriber that falls behind beyond the buffer is told it lost
      events (and resumes from the record store).
- [x] Events are scoped: a subscription with a session scope never receives other sessions' events.
- [x] Event payloads take redacted types only (FR-EVT-07).
- [ ] Phase 1 emits `session.started`, `session.ended`, `session.state_changed`, `session.idle`, `command.finished`
      (telemetry), `cwd.changed`. *Pending: the payload types and the session start/transition helpers exist and
      are tested; the emitters are wired by KNSH-021 (human telemetry) and KNSH-056 (`knsh agent`).*

*`events.subscribe` and `events.unsubscribe`*

- [x] `events.subscribe {session_id?, since_seq?}` returns a subscription ID, then sends events as notifications in
      `seq` order.
- [x] With `since_seq` inside the buffer, delivery resumes exactly after it; outside the buffer, the reply says how
      far back the buffer reaches.
- [x] `events.unsubscribe` stops delivery; closing the connection ends all its subscriptions.
- [ ] Output chunk events carry bytes as binary stream frames (when they exist in later phases). *Pending: no
      output chunk event exists in phase 1 (KNSH-053).*

**Unit tests**
*Event bus*

- `seq_is_gapless_per_session` — FR-EVT-02.
- `buffer_keeps_last_10000_events` — FR-EVT-03.
- `slow_subscriber_does_not_block_publisher` — at-most-once beyond buffer (FR-EVT-04).
- `scoped_subscription_never_sees_other_sessions` — FR-EVT-01.

*`events.subscribe` and `events.unsubscribe`*

- `resume_from_since_seq_has_no_duplicates_or_gaps` — FR-EVT-03.
- `since_seq_outside_buffer_reports_oldest_available` — at most once.
- `disconnect_ends_subscriptions` — resource cleanup.
