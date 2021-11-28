#!/bin/bash
# Generate an SVN-compatible diff against the tip of the tracking branch

# Get the highest revision number
REV=`git log -1 --pretty=%B oscam-svn | grep git-svn-id | sed -n -e 's/^.*trunk@\([0-9]*\) .*$/\1/p'`

# Then do the diff from the highest revision on the current branch and convert to SVN format
git diff --no-prefix --no-indent-heuristic $(git rev-list --date-order --max-count=1 oscam-svn) $*  -- :^.*  :^git-svn-diff.sh |
sed -e "/--- \/dev\/null/{ N; s|^--- /dev/null\n+++ \(.*\)|--- \1	(nonexistent)\n+++ \1	(working copy)|;n}" \
    -e "s/^--- .*/&	(revision $REV)/" \
    -e "s/^+++ .*/&	(working copy)/" \
    -e "s/^\(@@.*@@\).*/\1/" \
    -e "s/^diff --git [^[:space:]]*/Index:/" \
    -e "s/^index.*/===================================================================/" \
    -e "/^new file mode [0-9]\+$/d" \
    -e "/^deleted file mode [0-9]\+$/d"
