# KNSH-113 — Landlock and seccomp in `knsh-exec`

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Sandbox | XL (8) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | `knsh-exec`, `knsh-sandbox` | platform-support.md (Sandbox), FR-SBX-01 – FR-SBX-10, NFR-SUP-01 |

**Description.** As the engine on Linux, I need `knsh-exec` to apply Landlock file rules and a seccomp filter
(namespaces where available) before exec, so that envelopes and supervised lines are confined by the kernel.

Scope: compile the same policy into a Linux profile format (Landlock rulesets, seccomp BPF), apply it in the
single-threaded trampoline with hand-written syscall declarations (std only, no `libc` crate in `knsh-exec`),
`no_new_privs`, executable rules (Landlock execute rights), process-information limits, and the fixed denies.

**Acceptance criteria**
- [ ] Every row of the profile table in `sandbox-profiles.md` has a Linux equivalent or is reported as unsupported in
      `hello`.
- [ ] Fixed write denies and engine-path denies hold on Linux.
- [ ] If the kernel lacks Landlock, the probe reports `sandbox: none` and agent sessions refuse to start.
- [ ] `knsh-exec` stays std-only and single-threaded.

**Unit tests**
- `compiler_emits_landlock_rules_for_write_roots`
- `compiler_denies_engine_paths`
- `seccomp_filter_blocks_unlisted_socket_families`
- `probe_reports_none_without_landlock`

**Integration tests**
- Container tests: write outside roots fails, exec from an untrusted folder fails, `ptrace` of another process fails.

**Notes.** Seatbelt and Landlock have different expressiveness (e.g. read denies inside readable trees). Gaps must be
reported honestly via `hello`, not papered over.
