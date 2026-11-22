# Public release gate

English · [繁體中文](PUBLIC_RELEASE_zh-tw.md)

The public GitHub repository is never this working repository pushed as is. It is built fresh from one commit by [`scripts/public_export.py`](../scripts/public_export.py): only the files that `publish/allowlist.txt` names are copied, `publish/overlay/` adds what only the public repository has (its CI, Pages workflow and `.gitignore`), and the result gets one new commit with no earlier history. [`scripts/public_gate.py`](../scripts/public_gate.py) must pass on the tree before that commit and on the repository after it; any finding deletes the export.

## Never public

| Kind | Examples | Enforced by |
| --- | --- | --- |
| Secrets | passwords, API keys, bot keys, tokens, private keys, cookies, `/etc/jt-oz-bridge/secrets` | key/token rules, forbidden file types (`.pem`, `.key`, `.env`…) |
| Accounts and people | user names, e-mail addresses, chat user ids, real names | e-mail rule, owner-only term list |
| Hosts and networks | host names, internal domains, LAN addresses, ports of a real site, firewall and proxy files | IP rule (only RFC 5737 examples, loopback and `10.0.0.0/24`, the block tests use for made-up private addresses), owner-only term list, allowlist |
| Customers and projects | customer names, project names and paths, OpenCode project directories | owner-only term list |
| Live evidence | test-run reports, verification JSON of a real installation, database files, logs, backups | allowlist (never listed), forbidden file types |
| Session traces | OpenCode session ids, AI-assistant session links or notes | session-id rule, assistant-trace rule |
| Git history | old commits, their messages and authors | fresh single-commit repository; history is scanned too |

## The owner-only term list

Words that are private only for one site — its host names, accounts, customers, projects, real session ids — cannot be written in this repository, because the rule would publish them. The owner keeps them in a file outside the repository (mode 600) and passes it with `--private-terms`. One word per line, matched case-insensitively as a whole word; a line starting with `re:` is a regular expression. Matches of this list can never be reviewed away. Add a word whenever a new host, account, customer or project appears.

## Reviewed lines

Some tests feed fake keys or credentials on purpose, for example to prove that redaction removes them. Such a line may be listed in `publish/reviewed-findings.txt` as `path<TAB>rule<TAB>line digest<TAB>reason`; the gate prints the digest with each finding. Any change to the line changes its digest and voids the review. Review only made-up values, never a real one.

## Checklist

1. Commit the change in the private repository; the export reads that commit, not the working tree.
2. New public files are listed in `publish/allowlist.txt`; nothing private is listed there (the list is published too).
3. Update the owner-only term list for any new host, account, customer or project.
4. Build: `python -m scripts.public_export --out <new dir> --private-terms <file> --author "Name <e-mail>"`. It must end with `PASS`. The author and committer line is published as given and is the only text the gate lets through unchecked.
5. Read the file list of the export once (`git -C <dir> ls-files`) and spot-check new files by eye; rules catch patterns, not meaning.
6. In the export, run the public CI steps: `uv sync --locked`, `ruff check`, `ruff format --check`, `mypy src`, `pytest -q tests`.
7. Push the export to GitHub only after steps 4–6 passed. Pushing makes the content public at once and it may be copied even if deleted later; if anything private is ever pushed, rotate that secret first, then rewrite the public repository.
8. Release artifacts (wheel, CycloneDX SBOM, checksums) come from the full gate of the same commit.
