#!/bin/sh
# Builds the user guide (mkdocs.yml) into site-docs/ for https://bearstouch.com/knsh/docs/.
# Needs python3. Uses .venv-docs/ with the pinned docs-theme/requirements.txt.
set -eu
cd "$(dirname "$0")/.."

if [ ! -x .venv-docs/bin/mkdocs ]; then python3 -m venv .venv-docs; fi
.venv-docs/bin/pip install --quiet --disable-pip-version-check -r docs-theme/requirements.txt

.venv-docs/bin/mkdocs build --strict --clean --config-file mkdocs.yml

# The landing site's CSP allows no inline or third-party scripts; fail here rather than on the live site.
if grep -rEl '<script>|<script [^>]*src="https?://' site-docs --include='*.html'; then
    echo "error: inline or external <script> in the user guide (see files above)" >&2; exit 1
fi
if grep -rl 'fonts.googleapis.com' site-docs --include='*.html'; then echo "error: Google Fonts link in the user guide" >&2; exit 1; fi
echo "User guide built in site-docs/"
