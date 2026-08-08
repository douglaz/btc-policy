# AGENTS.md

<!-- agent-discipline-v1 -->

## Working agreement

These rules are here because agents get them wrong by default, not because they
are good general advice.

**Edits must be verified, not assumed.** Prefer your harness's edit tool: it
fails loudly when the target text does not match. `sed -i` and `str.replace()`
do the opposite — a pattern that matches nothing changes nothing, exits 0, and
prints whatever success message you wrote. Batching several edits into one
scripted call is the usual reason this happens, and the saved tool calls are not
worth it. If you do script an edit, assert the target exists before replacing and
make the success message conditional on that assert, then grep the file
afterwards for both the new text and the absence of the old. Prose and markdown
are where this bites hardest: nothing compiles a README, so a silently skipped
edit survives and gets reported as done.

The same tools also corrupt without failing. In a `sed` replacement string `&`
means "the whole match", so substituting a value containing `&&` — any shell
command that chains, which is most of them — silently doubles it and reports
success. Substitute with something that treats the replacement as a literal, and
grep for the result afterwards.

**Never pipe a gate through `tail`, `head`, or `grep`.** A pipeline's exit status
is the last command's, and `tail` always succeeds, so a failing build reports
exit 0. Redirect and capture the real code:

```bash
<gate> > /tmp/gate.log 2>&1; echo "EXIT=$?"
```

Then read the log. Note the `;` — not `|`. This line is for a human or agent to RUN and
READ — `$?` is the gate's status and `echo` prints it. Do not embed it in a script and
branch on the pipeline's status, which is `echo`'s and therefore always 0; if you need to
propagate the result, capture it (`status=$?`) and exit with it.

**"Passing", "clean", "working", "verified", and "done" require a command and an
exit code.** If you cannot show one, say what you actually observed instead. This
is the single most common way an agent reports success it did not have.

**Reviewers read code; they do not run it.** A clean review — human, bot, or
model — is not a passing build. Run the gate yourself before calling anything
done.

**A test that has never failed has proven nothing.** When you add one for a bug,
watch it go red against the unfixed code first. A test asserting behaviour that
was already correct is indistinguishable from a test asserting nothing.

Gate for this repo — three of the four legs of CI's `check` matrix, in the same form:

```
nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'
```

Keep it matching `.github/workflows/ci.yml`. A weaker local gate is worse than none: it
returns 0 on a tree CI will reject, so "I ran the gate" stops meaning "CI will pass". Both
details here are load-bearing — without `fmt` a non-rustfmt-clean edit passes locally and
fails CI, and without `--locked` cargo silently *regenerates* `Cargo.lock` on drift instead
of reporting it, validating a dependency graph that is not the committed one.

Not included, and this is the gap to hold in mind: the matrix's fourth leg `regtest-backend`,
which needs `bitcoind` and runs `#[ignore]`d tests, and the separate `launch-gate` job
(`attack all` + all three demos, ~47 min measured). So a tree that breaks the bitcoind backend
passes this gate while CI goes red — the one case where "I ran the gate" does not imply "CI
will pass". Run those two when touching chain-facing or custody-critical code; CI runs them on
every push regardless.

<!-- end-agent-discipline -->

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (open, unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only open, unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status                                    # Check what changed
br sync --flush-only || exit 1                # Export beads to JSONL FIRST — see below
git add <files> .beads/issues.jsonl           # Stage code AND the fresh export
git status                                    # Confirm the export is staged
git commit -m "..."                           # Commit everything
git push                                      # Push to remote
```

**The order matters and this block had it backwards.** `br sync --flush-only` REWRITES
`.beads/issues.jsonl`, so staging before syncing commits the pre-sync file and silently
drops the bead updates — the work is closed in the local DB and open in the repo. Sync
first, then stage, then confirm. And check the sync's exit code: the automatic flush that
follows a mutating command like `br close` swallows its own error, so `br close` can exit 0
with nothing written; only an explicit `br sync --flush-only` reports the failure.

<!-- LOCAL EDIT: this sits inside the br-managed block and `br agents --update` will revert
     it. Tracked as btc-policy-gc8 to push the fix upstream. -->


### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->
