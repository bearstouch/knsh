# Hooks

A hook is an executable registered in the user's configuration for `command.proposed`, with an optional match. Hooks run only for supervised agent commands, in the supervisor, before policy. The registration format is in [../models/hook.md](../models/hook.md); authoring guidance is in [../integrations/hooks.md](../integrations/hooks.md).

## Execution

| ID | Requirement |
| --- | --- |
| FR-HOOK-01 | Hooks must run only for supervised agent commands, in the supervisor, before policy evaluation. Human sessions run no hooks. |
| FR-HOOK-02 | A hook must receive the `command.proposed` event as JSON on stdin and answer on stdout with a verdict. |
| FR-HOOK-03 | A hook that prints nothing must be judged by its exit code: 0 is allow, 2 is deny. |
| FR-HOOK-04 | Any error or timeout must be a deny. There must be no way to make a hook fail open for agents. |
| FR-HOOK-05 | Each hook's run time must be reported per record, up to its timeout. |
| FR-HOOK-06 | Hooks run with the user's privileges outside any sandbox. |
| FR-HOOK-07 | Envelopes must not be able to read or write the hook configuration, so an agent cannot register or edit a hook. |

## Verdicts

| Verdict | Effect |
| --- | --- |
| `allow` | No objection |
| `deny` | Refuse, with a reason shown to the agent |
| `ask` | Escalate to the authority |
| `rewrite` | Replace the line; later hooks see the new line |
| `annotate` | Add labels to the record; no decision |

## Combining verdicts

| ID | Requirement |
| --- | --- |
| FR-HOOK-10 | Hooks must run in the order declared. The first `deny` stops the chain. |
| FR-HOOK-11 | Policy must be evaluated after hooks, on the possibly rewritten line. |
| FR-HOOK-12 | The final verdict must be the most restrictive of all: deny, then ask, then allow. |
| FR-HOOK-13 | A rewrite must apply only when the final verdict is not deny. |

## Rate limiting

| ID | Requirement |
| --- | --- |
| FR-HOOK-20 | If the same normalised line is denied 5 times within 60 seconds in one session, further attempts must be denied without asking anyone for 10 minutes, with `decision.source = rate_limit`. |
| FR-HOOK-21 | `command.denied_repeatedly` must be emitted once when rate limiting starts. |

Rate limiting keeps a looping agent from flooding the authority with asks.
