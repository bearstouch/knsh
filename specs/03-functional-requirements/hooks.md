# Hooks

A hook is an executable registered in the user's configuration for `command.proposed`, with an optional match. Hooks run only for supervised agent commands, in the supervisor, before policy. The registration format is in [../05-models/hook.md](../05-models/hook.md); authoring guidance is in [../08-integrations/hooks.md](../08-integrations/hooks.md).

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

- **Normalised line.** The line re-serialised with every resolved command's canonical absolute path (FR-LC-13),
  without leading or trailing whitespace; a line that cannot be re-serialised counts as its text as received.
  Subcommand options are not merged: `git -c a=b push` and `git push` are different lines.
- **Counted denials.** Every refusal of a parsed line by a rule, hook, the authority, the user or standalone rules,
  timeouts included. Not counted: cancellations (the caller left), lines refused before they were parsed, and the
  denials rate limiting itself makes. A line rewritten and then denied is counted under the line that was denied.
- **Window.** Five denials whose first and last are less than 60 seconds apart. Time comes from the injected clock.
- **While limited.** The line is denied right after it is parsed: no `command.proposed`, no hook and no ask. It is
  recorded (FR-REC-03) and reported with `command.denied`, with `source = rate_limit`. Once the 10 minutes pass,
  counting starts afresh, and a new limit emits `command.denied_repeatedly` again.
- **Memory.** Bounded per session and across sessions; dropping state can only lift a limit early.
