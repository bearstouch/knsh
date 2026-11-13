# Execution records

Each agent command line becomes a structured record. Fields are defined in [../05-models/execution-record.md](../05-models/execution-record.md).

| ID | Requirement |
| --- | --- |
| FR-REC-01 | Each agent command line that reaches lifecycle step 2 must produce exactly one record, whether it ran, was denied or was rewritten. |
| FR-REC-02 | `knshd` must write the record itself before replying to the client, so nothing is lost if the client dies. |
| FR-REC-03 | Denials and approvals must always be recorded, without output, because they are security events, regardless of recording settings. |
| FR-REC-04 | `command` must hold the line actually executed, after any rewrite, with secrets redacted; `rewritten_from` must hold the original line when a rewrite was applied. |
| FR-REC-05 | Redaction must run before anything is stored ([secrets](secrets.md#redaction)). Hooks and the authority must see the same redacted text. |
| FR-REC-06 | `stdout` and `stderr` must be stored only when output recording is on, capped at 1 MB each by default, after which head and tail are kept. |
| FR-REC-07 | Retention must default to 30 days or 2 GB, whichever comes first, configurable per profile. |
| FR-REC-08 | Records must be queried only through `records.query` and `records.output`. The SQLite file is an internal format, not an API. |
| FR-REC-09 | Human telemetry records, when recording is on, must hold only `command`, `cwd`, times and `exit_code`. |
| FR-REC-10 | `knsh forget --session <id>` or `--since <date>` must delete records; `--with-checkpoints` deletes their checkpoints too. |
| FR-REC-11 | Secret values must never be stored in records; `secrets_injected` holds names only. |
