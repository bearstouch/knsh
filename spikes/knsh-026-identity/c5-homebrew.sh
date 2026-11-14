#!/bin/bash
# KNSH-026 C5, Homebrew part: a real `brew install --build-from-source` of the Keychain probe
# (as "knshd") from a throwaway local tap, then `brew reinstall` and `brew upgrade`, reading
# the same Keychain item after each step.
#
# Creates the tap knsh-spike/k026 and the formula knsh-spike-kc, and removes both at the end.
# Writes results/c5-<macOS version>-homebrew.tsv.
set -o pipefail
source "$(dirname "$0")/helpers/common.sh"

export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 HOMEBREW_NO_ANALYTICS=1 \
    HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_CLEANUP=1

W=$OUT/brew
rm -rf "$W"
mkdir -p "$W"
# Both versions ship the same kc.c: the formula's -DBUILD=<n> is what makes 2.0 different code.
for v in 1 2; do
    tar czf "$W/knsh-spike-kc-$v.tar.gz" -C "$SRC" kc.c
done

brew tap-new --no-git knsh-spike/k026 >/dev/null 2>&1
TAP=$(brew --repository knsh-spike/k026)
cleanup() {
    brew uninstall --force knsh-spike/k026/knsh-spike-kc >/dev/null 2>&1
    brew untap knsh-spike/k026 >/dev/null 2>&1
}
trap cleanup EXIT

formula() { # formula <version number>: the formula for source tarball <n>, version <n>.0
    cat >"$TAP/Formula/knsh-spike-kc.rb" <<EOF
class KnshSpikeKc < Formula
  desc "KNSH-026 spike: Keychain probe built by Homebrew (throwaway)"
  homepage "https://example.invalid/knsh-spike"
  url "file://$W/knsh-spike-kc-$1.tar.gz"
  version "$1.0"
  sha256 "$(shasum -a 256 "$W/knsh-spike-kc-$1.tar.gz" | cut -d' ' -f1)"
  def install
    system ENV.cc, "-O1", "-DBUILD=$1", "-o", "knshd", "kc.c", "-framework", "Security", "-framework", "CoreFoundation"
    bin.install "knshd"
  end
end
EOF
}

B=$(brew --prefix)/bin/knshd
S=knsh.spike.026.brew
TSV=$RESULTS/c5-$OSVER-homebrew.tsv
printf 'step\tsignature\tresult\n' >"$TSV"
row() { printf '%s\t%s\t%s\n' "$1" "$(sig_summary "$B")" "$2" | tee -a "$TSV"; }
kc() { limit 20 "$B" "$1" legacy "$S" acct; } # kc <op>: run the installed probe on the test item

formula 1
brew install --build-from-source knsh-spike/k026/knsh-spike-kc >/dev/null 2>&1 || exit 1
# A leftover item from an interrupted run would turn "add" into a duplicate error.
kc delete >/dev/null 2>&1
row "1.0 installed, creates item" "$(kc add)"
row "1.0 reads" "$(kc read)"
brew reinstall --build-from-source knsh-spike/k026/knsh-spike-kc >/dev/null 2>&1
row "1.0 reinstalled (rebuilt from the same source) reads" "$(kc read)"
formula 2
brew upgrade --build-from-source knsh-spike/k026/knsh-spike-kc >/dev/null 2>&1
row "2.0 (brew upgrade) reads" "$(kc read)"
row "2.0 deletes" "$(kc delete)"
scrub "$TSV"
