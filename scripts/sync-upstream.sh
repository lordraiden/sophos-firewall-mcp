#!/bin/sh
# Sync this fork with upstream, following docs/UPSTREAM-SYNC.md.
#
# Policy in one line: upstream is MERGED, never rebased; `main` is never rewritten. Anything pinned to a
# commit here must keep meaning what it meant when it was pinned.
#
# Deliberately absent: --force, reset, rebase, and any automatic conflict resolution. A sync script that
# resolves conflicts on its own is a script that loses work quietly.
#
# Usage:
#   scripts/sync-upstream.sh            merge upstream/main into the current branch
#   scripts/sync-upstream.sh --check    fetch and report what is missing; change nothing
set -eu

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/jelmervdm/sophos-firewall-mcp.git}"
BRANCH="${UPSTREAM_BRANCH:-main}"
MODE="${1:-merge}"

cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain)" ]; then
    echo "sync-upstream: uncommitted changes. Commit or stash them first -- a half-merged tree is how a"
    echo "               sync becomes an incident."
    exit 1
fi

if ! git remote | grep -qx upstream; then
    echo "sync-upstream: adding remote 'upstream' -> $UPSTREAM_URL"
    git remote add upstream "$UPSTREAM_URL"
fi

echo "sync-upstream: fetching upstream..."
git fetch --quiet upstream

BEHIND=$(git rev-list --count "HEAD..upstream/$BRANCH")
AHEAD=$(git rev-list --count "upstream/$BRANCH..HEAD")
CURRENT=$(git rev-parse --abbrev-ref HEAD)

echo "sync-upstream: branch '$CURRENT' is $AHEAD commit(s) ahead of upstream, $BEHIND behind."

if [ "$BEHIND" -eq 0 ]; then
    echo "sync-upstream: nothing to merge."
    exit 0
fi

echo "sync-upstream: upstream commits not present here:"
git --no-pager log --oneline "HEAD..upstream/$BRANCH" | sed 's/^/  /'
echo "sync-upstream: files they touch:"
git --no-pager diff --name-only "HEAD..upstream/$BRANCH" | sed 's/^/  /'

if [ "$MODE" = "--check" ]; then
    echo "sync-upstream: --check requested, stopping before the merge."
    exit 0
fi

echo "sync-upstream: merging upstream/$BRANCH (no rebase, no force)..."
if ! git merge --no-ff --no-edit "upstream/$BRANCH"; then
    echo ""
    echo "sync-upstream: merge stopped on a conflict. The merge is left in progress on purpose:"
    echo "               resolve it, run the test suite, and commit. To back out safely:"
    echo "                 git merge --abort"
    exit 2
fi

echo ""
echo "sync-upstream: merged. Run the suite before pushing:"
echo "  env -u PYTHONPATH -u PYTHONHOME ./venv/bin/python -m pytest tests/ -q"
