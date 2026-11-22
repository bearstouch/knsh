# User guide (bearstouch.com/knsh/docs)

End-user documentation for Kinetic Shell, built from the Markdown in `docs/` by `scripts/build-docs.sh` with
`mkdocs.yml`.

```sh
scripts/build-docs.sh          # builds site-docs/ (needs python3; uses .venv-docs/)
.venv-docs/bin/mkdocs serve    # live preview at http://127.0.0.1:8000/
```

`site-docs/` is plain static HTML, ready to copy to `bearstouch.com/knsh/docs/`.

- `docs/` holds the guide: the home page, getting started, one page per topic under `guides/` and the lookups under
  `reference/`. The nav in `mkdocs.yml` lists every published page; a page not in the nav isn't linked.
- `docs-theme/overrides/` is the Material theme override that keeps every page within the landing site's CSP (no inline
  scripts, no third-party fonts or scripts). The build script fails if either appears in the output.
- `docs-theme/requirements.txt` pins the toolchain.

## Writing the guide

Write for someone who uses `knsh`, not for someone who builds or tests it.

- **Task first.** Say what a feature is for in a sentence or two, then how to use it: the command, what happens, and what
  to do when something goes wrong. Second person, present tense. Short paragraphs. `##` sections named after tasks.
- **No development language.** No requirement IDs, story numbers, phases, "proposed" or "pending" notes, acceptance checks,
  crate, module or file names unless the user types or sees them (a command, a settings file, a key in a profile).
- **Only what ships.** Describe behavior that works. Leave out anything planned. When something works only partly, say
  so plainly in a "Limits" section.
- **Exact names.** Commands, options and keys in `code`, exactly as `knsh --help` and the code show them. Check against
  the binary before publishing. Shortcuts as `<kbd>Ctrl</kbd>`.
- **Keep the limits users hit.** Size caps, confirmations, what is never stored, what needs Touch ID.
- **Links.** Relative links between guide pages (`../guides/policy.md`). Don't link to the specs or contributor pages.
- Use admonitions sparingly (`!!! tip`, `!!! warning`). Plain, calm, specific.

When user-visible behavior changes, update the matching page in the same change.
