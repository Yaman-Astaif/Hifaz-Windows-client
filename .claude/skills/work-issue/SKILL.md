---
name: work-issue
description: Take one GitHub issue from start to a pull request using the planner, implementer, reviewer and protocol-keeper agents, and write a work report. Use when the owner says "work on issue #N" or runs /work-issue N.
argument-hint: <issue number>
---

# Work on one issue, end to end

The owner asking for this issue is the go-ahead to build it. Work without
stopping for questions unless a step below says to stop. Never merge, tag or
release: the owner does that.

Keep a task list with one item per step so progress is visible.

## 1. Read the issue
- `gh issue view $ARGUMENTS --comments`
- If it is closed, already has an open PR, or is too vague to build, stop and
  say why.

## 2. Branch
- `git status --short`: if there are uncommitted changes, stop and tell the
  owner; never stash or discard them.
- If the current branch is not `main`, say so in the reply: switching away
  takes that branch's files (for example an unmerged pull request) out of the
  working tree. Nothing is lost; they stay on their branch.
- `git fetch origin` then `git switch -c agent/$ARGUMENTS-<short-slug> origin/main`
  (if the branch exists, switch to it and continue).

## 3. Start the work report
- Create `docs/agent-log/<YYYY-MM-DD>-issue-$ARGUMENTS.md` from
  `docs/agent-log/TEMPLATE.md`. Fill in the request now; fill in each other
  section as its step finishes.

## 4. Plan: `planner` agent
- Give it the issue text and ask for a plan.
- If its plan has open questions that change what gets built, post them on
  the issue (`gh issue comment`), note them in the report, and stop here.
- Post the plan summary on the issue as a comment.

## 5. Build: `implementer` agent
- Give it the full plan. It must end with `make check` passing.

## 6. Review: `reviewer` agent
- Give it the issue and the plan (not the implementer's reasoning).
- If there are BLOCKING findings, send them to the `implementer`, then review
  again. At most 2 rounds; if blocking findings remain after that, open the PR
  as a draft (`gh pr create --draft`) and list them at the top.

## 7. Protocol check: `protocol-keeper` agent
- Only if the change touches the client API, `docs/client-protocol.md`, the
  test vectors or versions. If it reports OUT OF STEP, say in the PR which
  repository needs a follow-up issue, and create that issue with
  `gh issue create` in the right repository.

## 8. Finish
- Complete the work report and commit it on the branch.
- `git push -u origin <branch>`
- `gh pr create` once, with title `<issue title> (#$ARGUMENTS)` and a body made
  of the finished work report, ending with `Closes #$ARGUMENTS`. Write the body
  to a file first (`--body-file`). Do not edit the pull request afterwards
  (`gh pr edit` fails on this repository, and PATCH through `gh api` is
  blocked); to add something, use `gh pr comment`.
- Comment on the issue with the PR link.
- Reply to the owner in a few lines: the PR link, `make check` result, review
  outcome, anything left open.
