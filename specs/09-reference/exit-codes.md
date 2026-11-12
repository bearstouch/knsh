# Exit codes

Exit status of `knsh -c` and supervised lines follows bash.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1–125 | The command's own exit status |
| 126 | Found but not executable (POSIX), **or denied by policy, hook, authority or rate limit**. On denial the reason is always printed on stderr and kept in the record |
| 127 | Command not found |
| 128 + n | Killed by signal n |

API error codes are in [../api/errors.md](../api/errors.md).
