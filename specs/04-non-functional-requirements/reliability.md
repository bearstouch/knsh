# Reliability and standalone mode

The engine must stay safe when parts of it are missing: fail closed for agents, open for humans.

## Requirements

| ID | Requirement |
| --- | --- |
| NFR-REL-01 | If `knshd` cannot be reached, no agent line may run (there is no supervisor) and agent network must be blocked (there is no proxy). `knsh -c` then runs nothing, prints that the supervisor is unavailable and that the line did not run on stderr, and exits **126**, as for a denial (KNSH-049). It never runs the line itself, whatever fails. |
| NFR-REL-02 | If `knshd` cannot be reached, human sessions must continue normally; telemetry is dropped. |
| NFR-REL-03 | launchd must restart `knshd` if it crashes while envelopes exist, so the unreachable case is brief. |
| NFR-REL-04 | After `knshd` returns, it must rescan checkpoint roots and mark the gap during which envelope changes were not checkpointed. |
| NFR-REL-05 | `knshd` must write each execution record before replying to the client. |
| NFR-REL-06 | Grants and pushed policy must survive `knshd` restarts; authority-supplied secrets need not. |
| NFR-REL-07 | Any hook error or timeout must deny the line. |
| NFR-REL-08 | The engine must never silently fall back to a different policy or a weaker backend; missing backends are reported as `none`. |
| NFR-REL-09 | The engine must work fully without an authority. |

## Standalone mode

| Situation | Human session | Agent session |
| --- | --- | --- |
| No authority connected | Unaffected | Local profiles apply; asks can be approved with `knsh approve` (Touch ID) or are denied at the timeout |
| Pushed policy expired | Unaffected | Paused until the authority returns or the user picks a local profile with Touch ID |
| `knshd` unreachable | Unaffected; telemetry is dropped | No line runs (no supervisor) and network is blocked (no proxy). The envelope keeps confining the agent, but changes it makes directly are not checkpointed until `knshd` returns, rescans and marks the gap |
| Hook fails or times out | No hooks run | The line is denied |
| Shadow not ready | Not applicable | Lines touching that root wait, or fail with `-32010` |
| No working sandbox backend | Unaffected | Agent sessions refuse to start (`sandbox: none`) |

An agent session never gets a yes/no prompt in its own terminal, because the agent driving that terminal could answer it.
