# KNSH-026 spike: code-signed identity (C5, C6, C7)

Throwaway prototypes that check what `knshd`'s code signature can protect: Keychain items (C5), the
LocalAuthentication prompt from a launchd agent (C6), and XPC peer code-signing checks in both directions (C7). The
results feed policy signing (KNSH-065), the authentication prompt (KNSH-064), the control service (KNSH-067) and
authority trust (KNSH-068). Nothing here is shipped, built by Cargo or called by the product.

**The written result is in [verification claims](../../specs/07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7)**,
with proposed decisions 11 to 13 in [decisions](../../specs/09-reference/decisions.md).

## Files

| Path | What it is |
| --- | --- |
| `c5-keychain.sh` | C5: one Keychain probe signed ad hoc, as Homebrew leaves it, and with Developer ID. Build 1 creates an item; build 2, an unrelated binary and a sandboxed binary try to read, overwrite and delete it. Also: switching between Homebrew and Developer ID builds, overwrites by code outside the team, and the data-protection keychain |
| `c5-homebrew.sh` | C5: a real `brew install --build-from-source` of the probe from a throwaway local tap, then `brew reinstall` and `brew upgrade`. Removes the tap and formula when done |
| `c6-touchid.sh` | C6: the LocalAuthentication probe from the terminal and as a launchd agent in the GUI domain (`gui/<uid>`) and the background domain (`user/<uid>`). Prompting cases need a person at the Mac |
| `c7-xpc.sh` | C7: a launchd-declared Mach service and a client, each signed several ways: requirement checks, exec after send, impostor services, a second job claiming the name, and a listener outside launchd |
| `src/kc.c` | Keychain probe: `add`, `read`, `update`, `delete`, `acl` on the legacy (file) keychain or the data-protection keychain, with user interaction disabled |
| `src/la.m` | LocalAuthentication probe: security-session attributes, `canEvaluatePolicy`, then `evaluatePolicy` with a reason text and a timeout |
| `src/xpc_service.c`, `src/xpc_client.c` | XPC service (checks by `xpc_connection_set_peer_code_signing_requirement` or by `SecCodeCreateWithXPCMessage`, and logs what a pid-based check would have decided) and client |
| `helpers/common.sh` | Signing helpers (`sign_adhoc`, `sign_devid`, `sign_homebrew`), `limit` (hard time limit), `scrub` (replaces home, user name, team ID and signer name with placeholders), launchd job helpers |
| `results/` | Results per macOS version. Screenshots of the prompts are never committed: they show the whole desktop |

## Running

Run as a normal user, never with `sudo`. Every probe has a hard time limit. Binaries are built under
`~/.cache/knsh-spike-026/` (override with `KNSH_SPIKE_026_DIR`), not in the repository: launchd blocks on a TCC prompt
when a job's program sits under `~/Desktop`, `~/Documents` or `~/Downloads` (KNSH-012).

```sh
spikes/knsh-026-identity/c5-keychain.sh     # about 30 s; creates and deletes items named knsh.spike.026.*
spikes/knsh-026-identity/c5-homebrew.sh     # about 1 min; needs Homebrew
spikes/knsh-026-identity/c7-xpc.sh          # about 2 min; loads and unloads launchd jobs knsh.spike.026.c7*
spikes/knsh-026-identity/c6-touchid.sh noui                          # no prompt shown
KNSH_SPIKE_SCREENSHOT=1 spikes/knsh-026-identity/c6-touchid.sh agent-prompt 120   # shows a prompt: answer it
KNSH_SPIKE_SCREENSHOT=1 spikes/knsh-026-identity/c6-touchid.sh bg-prompt 120      # same, background domain
```

The Developer ID cases need a "Developer ID Application" identity in the login keychain (the first one found is used;
set `KNSH_SPIKE_IDENTITY` to choose). Without one, C5 records only the ad-hoc and Homebrew schemes and C7 does not run.
Signing uses `--timestamp=none`, so nothing goes over the network.

`c5-keychain.sh` disables Keychain user interaction in every probe, so a would-be "allow access" dialog comes back as
status `-25293` (the probe was not trusted) instead of appearing. It prints any `knsh.spike.026.*` item it leaves
behind.

## Still to do

- Rerun everything on macOS 14 and 15 (C7's first criterion asks for both).
- C6 with the lid open, to see the Touch ID sensor used (with the lid closed, the prompt falls back to the password).
- C6 cancellation and timeout outcomes: in every run, the person at the Mac typed the password.
- C6 from an SSH login with nobody logged in at the console (Remote Login was off on the test machine).
- The data-protection keychain with a provisioning profile, which needs an App ID from the Apple developer portal and
  `knshd` inside an app bundle.
