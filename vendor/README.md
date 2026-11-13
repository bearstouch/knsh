# Vendored dependencies

Every third-party crate the workspace builds is checked in here, so that `cargo build --workspace --offline --locked`
works with no network (NFR-SUP-03). `.cargo/config.toml` replaces crates.io with this directory. Never edit vendored
files by hand: `cargo` verifies them against `.cargo-checksum.json`.

## Policy

Each runtime crate needs a written justification, review, an exact version pin (`=x.y.z` in the root `Cargo.toml`) and
vendoring (NFR-SUP-02; `specs/04-non-functional-requirements/supply-chain.md`). The test
`xtask/tests/dependency_policy.rs` fails if `Cargo.lock` lists any other third-party crate.

## Crates

| Crate | Version | Licence | Used by | Justification |
| --- | --- | --- | --- | --- |
| `libc` | `=0.2.191` | MIT OR Apache-2.0 | `knsh-platform` only | Raw FFI declarations (types, constants, function signatures) for the system C library: `fork`/`exec`, `kqueue`, sockets, `audit_token` lookups, file modes and flags. It contains no logic of its own, is maintained by the Rust project, and hand-writing the same declarations would be error-prone (wrong struct layouts are memory-safety bugs). `knsh-exec` does not use it and declares its few `extern` functions by hand (NFR-SUP-01). |

### Test-only crates (fuzzing)

Used only by `fuzz/` (KNSH-005), a separate workspace that is never built with the shipped crates; they are absent from
the root `Cargo.lock` (NFR-SUP-05). Pinned by `fuzz/Cargo.toml` (`libfuzzer-sys = "=0.4.13"`) and `fuzz/Cargo.lock`.

| Crate | Version | Licence | Why |
| --- | --- | --- | --- |
| `libfuzzer-sys` | `=0.4.13` | (MIT OR Apache-2.0) AND NCSA | libFuzzer runtime and the `fuzz_target!` macro used by `cargo fuzz` |
| `arbitrary` | 1.5.0 | MIT OR Apache-2.0 | dependency of `libfuzzer-sys` |
| `cc` | 1.11.2 | MIT OR Apache-2.0 | builds libFuzzer's C++ sources (dependency of `libfuzzer-sys`) |
| `find-msvc-tools` | 0.1.15 | MIT OR Apache-2.0 | dependency of `cc` |
| `jobserver` | 0.1.35 | MIT OR Apache-2.0 | dependency of `cc` |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 | dependency of `cc` |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | dependency of `jobserver` |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 | dependency of `getrandom` |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | dependency of `getrandom` (UEFI targets only; used under MIT) |
| `libc` | 0.2.191 | MIT OR Apache-2.0 | same pinned copy as above |

## Updating

```sh
# 1. bump the exact pin in the root Cargo.toml, then (with network access, outside the offline config):
mv .cargo/config.toml /tmp/knsh-config.toml
cargo update -p libc --precise <version>
rm -rf vendor/libc-* && cargo vendor --versioned-dirs vendor
mv /tmp/knsh-config.toml .cargo/config.toml
# For the fuzz crates, vendor both lockfiles at once (`cargo vendor` replaces the directory,
# so restore this README afterwards with `git checkout vendor/README.md`):
#   cargo vendor --locked --versioned-dirs --sync fuzz/Cargo.toml vendor
# 2. update the table above, run scripts/check.sh, and explain the bump in the PR.
```
