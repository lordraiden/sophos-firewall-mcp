# Upstream sync policy

**Decision: this fork diverges cleanly. `main` is never rewritten, and upstream is merged into it.**

Recorded to settle issue #5. The reasoning, because a policy without its reason gets "fixed" by the next
person:

- This fork is now the **maintained copy**: the local harness installs from it, so `main` has to carry the
  fixes. A policy that keeps `main` a byte-for-byte mirror of upstream would leave consumers without them.
- `main` is **never rebased or force-pushed**. Anything may be pinned to a commit here; rewriting history
  would silently change what "install from `main`" means, which is exactly the failure a fork is supposed to
  avoid.
- Upstream arrives as an ordinary **merge commit** (`git merge upstream/main`). The history honestly shows
  where our line joins theirs, and a conflict is resolved once instead of at every rebase.

## Remote setup

`upstream` is not stored in the repository — remotes are local state — so the first sync adds it:

```bash
git remote add upstream https://github.com/jelmervdm/sophos-firewall-mcp.git
```

`scripts/sync-upstream.sh` does that itself if the remote is missing.

## Routine

```bash
scripts/sync-upstream.sh --check   # fetch, report how far behind, change nothing (default is safe too)
scripts/sync-upstream.sh           # fetch + merge upstream/main into the current branch
```

The script never rebases, never force-pushes and never resets. On conflict it stops and says so, leaving the
merge in progress for a human to finish — a script that resolves conflicts automatically is a script that
loses work quietly.

## Local fixes and upstream

The fix set in this fork came from real incidents (see `CHANGELOG.md`). Two rules:

1. **They stay local by default.** The fork owner has chosen not to propose them upstream so far; that is a
   deliberate decision, not an oversight, and it is recorded here so it is not "discovered" again.
2. **Proposing them upstream later is allowed and cheap.** Each fix is a self-contained branch with tests,
   which is exactly the shape an upstream PR needs. If one is accepted, drop it from this fork by merging
   upstream — no cherry-pick bookkeeping.

What must **not** happen: diverging silently. If upstream changes an API this fork also touches, the merge
conflict is the signal to reconcile, and it should be resolved in a named branch, not by ignoring it.

## Checking whether the fork still applies cleanly

Before a release or a risky change:

```bash
scripts/sync-upstream.sh --check
```

Reports the commit range that is missing and the files it touches, so a conflict can be anticipated while
there is still time to think.
