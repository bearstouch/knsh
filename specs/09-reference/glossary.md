# Glossary

| Term | Definition |
| --- | --- |
| **Actor** | Who a session belongs to: `human` or `agent` (with an `agent_id`), fixed at start |
| **Agent edit** | A file change made inside an envelope outside any supervised line, e.g. by the agent's built-in edit tool |
| **Approval hosts** | Hosts reachable only by commands whose class allows it or that were approved |
| **Authority** | The one trusted, code-signed client that makes decisions, pushes policy, grants, controls sessions and supplies secrets |
| **Capability probe** | The `knshd` component that detects which backends work on this machine |
| **Checkpoint** | The pre-images and post-image identities of the paths one change touched |
| **Checkpoint root** | A folder protected by checkpoints |
| **Concurrent set** | Overlapping supervised lines in one root, attributed and undone together |
| **Dynamic code** | Code whose effect the parser cannot know: `eval`, `source`, `sh -c`, interpreters with `-c`/`-e`, names from variables, unparseable input. Never inherits classes, network or secrets |
| **Envelope** | A sandboxed process tree started by `knsh agent`, confining an agent CLI and everything it runs directly |
| **Grant** | A time-limited rule added on top of a profile, usually after an approval |
| **Hook** | A user-registered executable that can allow, deny, ask, rewrite or annotate a proposed agent command |
| **Integration mode** | `knsh` hosting stock zsh or bash for humans, recording via `preexec`/`precmd` |
| **Irreversible** | A flag on lines whose effects checkpoints cannot undo (push, deploy, publish, remote writes) |
| **Native mode** | `knsh`'s own bash-compatible interpreter (phase 4) |
| **Possibly torn** | A file that was open for writing or memory-mapped during a change, or a SQLite database with journals; not restored without `force` |
| **Post-image identity** | Inode, size, modification time and (under 64 MB) content hash of a file after a change; restore requires a match |
| **Pre-image** | A file's contents before a change, or a marker that it did not exist |
| **Preset** | Profile settings for what a specific agent CLI needs (API host, config folder, proxy settings, classes) |
| **Profile (policy)** | A TOML policy describing what an agent may read, write, run and reach |
| **Profile (sandbox)** | A compiled Seatbelt profile for an envelope or a supervised line |
| **Project executable** | A binary found in an agent-writable place, e.g. `node_modules/.bin` |
| **Shadow** | A copy-on-write clone of a checkpoint root, kept current with file events |
| **Shim** | `sh`, `bash`, `zsh` entries first in the envelope's `PATH` that route to `knsh -c` |
| **Standalone mode** | Operation without an authority, with local profiles and Touch ID approvals |
| **Supervisor** | The part of `knshd` that decides on and spawns every agent shell command |
| **Trusted folder** | A folder from which name rules match binaries: `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin`, plus profile additions |
| **Trusted tool** | A tool a profile names to run without a per-command profile, only after approval or grant |
| **Uncertain** | A checkpoint taken while file events were dropped |
| **`unattended` profile** | The profile for non-interactive `knsh` outside any envelope: supervised, sandboxed, denied anything needing approval |
