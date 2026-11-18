# Developer-tool compatibility (KNSH-076)

Tested on macOS 26.6.2 (25G83), aarch64, on 2026-11-18. Each tool ran as a supervised line under its per-command profile and directly inside an envelope, through the real proxy to the real hosts (names resolved before the run by the system resolver). Profile: the project writable, every command allowed, `network.hosts` = example.com, github.com, registry.npmjs.org, pypi.org, files.pythonhosted.org, index.crates.io, static.crates.io.

| Tool | Variant | Version tested | Outside any sandbox (control) | Command profile | Envelope | Status | Documented |
| --- | --- | --- | --- | --- | --- | --- | --- |
| curl | HTTPS through the proxy (`HTTPS_PROXY`) | curl 8.7.1 (x86_64-apple-darwin25.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6 zlib/1.2.12 nghttp2/1.68.1 | exit 0 | exit 0 | exit 0 | **works** | works |
| git | HTTPS remote (`git ls-remote`) | git version 2.54.0 (Apple Git-157) | exit 0 | exit 0 | exit 0 | **works** | works |
| git | ssh remote (`git ls-remote git@github.com:…`) | git version 2.54.0 (Apple Git-157); OpenSSH_10.3p1, LibreSSL 3.3.6 | exit 0 | Exited(128): and the repository exists. | exit 128: and the repository exists. | **blocked** | blocked |
| npm | registry read (`npm view`) | npm 10.9.3 (node v22.20.0) | exit 0 | exit 0 | exit 0 | **works** | works |
| pip | package download (`pip download`) | pip 26.1.1 from /opt/homebrew/lib/python3.14/site-packages/pip (python 3.14) | exit 0 | exit 0 | exit 0 | **works** | works |
| cargo | crates.io sparse index and download (`cargo fetch`) | cargo 1.99.0 (5f94df478 2026-08-27) | exit 0 | exit 0 | exit 0 | **works** | works |
| Node HTTP clients | `fetch` (undici) | node v22.20.0 | exit 0 | Exited(1): ENOTFOUND | exit 1: ENOTFOUND | **blocked** | blocked |
| Node HTTP clients | `https.get` | node v22.20.0 | exit 0 | Exited(1): ENOTFOUND | exit 1: ENOTFOUND | **blocked** | blocked |
| Node HTTP clients | `fetch` (undici) | node v22.23.5 | exit 0 | exit 0 | exit 0 | **works** | works |
| Node HTTP clients | `https.get` | node v22.23.5 | exit 0 | exit 0 | exit 0 | **works** | works |
| Node HTTP clients | `fetch` (undici) | node v24.21.0 | exit 0 | exit 0 | exit 0 | **works** | works |
| Node HTTP clients | `https.get` | node v24.21.0 | exit 0 | exit 0 | exit 0 | **works** | works |
| Chromium (Playwright build) | headless render (`--dump-dom`) | Google Chrome for Testing 153.0.8010.12 (chromium_headless_shell-1243) | exit 0 | Signalled(11): [end of stack trace] | exit 139: [end of stack trace] | **needs a trusted tool** | needs a trusted tool |
| Chromium (Google Chrome) | headless render (`--dump-dom`) | Google Chrome 157.0.8103.79 | exit 0 | Signalled(6):  | exit 134:  | **needs a trusted tool** | needs a trusted tool |
| Playwright | Node driver launching Chromium |  | — | — | — | **pending**: Playwright's Node driver is not installed here (only its Chromium build, above); installing it from npm is left to a machine set up for it | needs a trusted tool |
| swift build | `swift build` | Apple Swift version 6.4 (swiftlang-6.4.0.34.1 clang-2100.3.34.1) | exit 0 | Exited(1): error: InternalError(description: "Internal error. Please file a bug at https://github.com/swiftlang/swift-package-manager/issues with this info. Failed to parse target info JSON from Swift frontend while executing command \'/Applications/X… | exit 1: error: InternalError(description: "Internal error. Please file a bug at https://github.com/swiftlang/swift-package-manager/issues with this info. Failed to parse target info JSON from Swift frontend while executing command \'/Applications/X… | **needs a trusted tool** | needs a trusted tool |
| swift build | `swift build --disable-sandbox` | Apple Swift version 6.4 (swiftlang-6.4.0.34.1 clang-2100.3.34.1) | exit 0 | Exited(1): error: InternalError(description: "Internal error. Please file a bug at https://github.com/swiftlang/swift-package-manager/issues with this info. Failed to parse target info JSON from Swift frontend while executing command \'/Applications/X… | exit 1: error: InternalError(description: "Internal error. Please file a bug at https://github.com/swiftlang/swift-package-manager/issues with this info. Failed to parse target info JSON from Swift frontend while executing command \'/Applications/X… | **needs a trusted tool** | needs a trusted tool |
| Bazel | `bazel build` of a one-file target | unknown | — | — | — | **pending**: Bazel (or Bazelisk) is not installed on this machine | needs a trusted tool |

Names each case's sandboxed runs asked the proxy to reach (the proxy resolves names; a tool that ignores it asks for none):

- curl, HTTPS through the proxy (`HTTPS_PROXY`): example.com
- git, HTTPS remote (`git ls-remote`): github.com
- git, ssh remote (`git ls-remote git@github.com:…`): none
- npm, registry read (`npm view`): registry.npmjs.org
- pip, package download (`pip download`): files.pythonhosted.org, pypi.org
- cargo, crates.io sparse index and download (`cargo fetch`): index.crates.io, static.crates.io
- Node HTTP clients, `fetch` (undici): none
- Node HTTP clients, `https.get`: none
- Node HTTP clients, `fetch` (undici): example.com
- Node HTTP clients, `https.get`: example.com
- Node HTTP clients, `fetch` (undici): example.com
- Node HTTP clients, `https.get`: example.com
- Chromium (Playwright build), headless render (`--dump-dom`): none
- Chromium (Google Chrome), headless render (`--dump-dom`): none
- swift build, `swift build`: none
- swift build, `swift build --disable-sandbox`: none

Hosts the proxy was asked for: example.com, files.pythonhosted.org, github.com, index.crates.io, pypi.org, registry.npmjs.org, static.crates.io.

**Pending** for every tool marked *needs a trusted tool*: running it as a trusted tool (`exec.trusted_tools`, FR-SBX-09) needs an approval or a grant made after Touch ID or the user's password, which an unattended run cannot give.
