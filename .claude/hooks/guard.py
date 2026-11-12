#!/usr/bin/env python3
"""Stop shell commands that only the owner may run.

Called before every Bash command (see .claude/settings.json). Exit 2 means
blocked; the reason goes to the agent so it can choose another way.

Blocked:
  - any commit or push while on main/master, any push to main/master
  - force-push, push --all / --mirror / --tags / --delete, pushing a v* tag
  - git tag (tags start releases; the owner makes them)
  - gh pr merge, gh release, gh secret, gh repo delete/edit/rename/archive,
    running the release workflow, DELETE/PUT/PATCH calls through gh api
  - deleting .git, the root or the home folder

The permission rules in settings.json say the same; this is the second lock.
Standard library only.
"""
import datetime
import json
import os
import re
import shlex
import subprocess
import sys

PROTECTED = re.compile(r"^(main|master)$")


def current_branch(cwd):
    try:
        out = subprocess.run(["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip()
    except Exception:
        return ""


def words_of(part):
    try:
        return shlex.split(part)
    except ValueError:
        return part.split()


def check(cmd, cwd):
    """Return the reason to block, or None."""
    for part in re.split(r"&&|\|\||;|\||\n", cmd):
        w = words_of(part.strip())
        if not w:
            continue
        line = " ".join(w)

        if re.match(r"^git(\.exe)?$", w[0]):
            i = 1
            while i < len(w) and w[i].startswith("-"):
                i += 2 if w[i] in ("-C", "-c") else 1
            if i >= len(w):
                continue
            sub, rest = w[i], w[i + 1:]
            if sub == "tag":
                return "creating or changing tags is for the owner (tags start releases)"
            if sub == "commit" and PROTECTED.match(current_branch(cwd)):
                return "committing directly on main is not allowed"
            if sub == "push":
                for a in rest:
                    if re.match(r"^(-f|--force.*|\+.*|--all|--mirror|--tags|--delete|-d|--follow-tags)$", a):
                        return "git push %s is not allowed" % a
                refs = [a for a in rest if not a.startswith("-")]
                for r in refs[1:]:  # refs[0] is the remote
                    dst = re.sub(r"^refs/heads/", "", r.split(":")[-1])
                    if PROTECTED.match(dst):
                        return "pushing to main is not allowed"
                    if re.match(r"^(refs/tags/)?v\d", dst):
                        return "pushing a version tag is not allowed"
                if len(refs) <= 1 and PROTECTED.match(current_branch(cwd)):
                    return "pushing while on main is not allowed"
            continue

        if re.match(r"^gh(\.exe)?$", w[0]) and len(w) >= 2:
            two = " ".join(w[1:3])
            if two.startswith("pr merge"):
                return "merging pull requests is for the owner"
            if w[1] == "release":
                return "releases are made by the owner"
            if w[1] == "secret":
                return "secrets are managed by the owner"
            if re.match(r"^repo (delete|edit|rename|archive)", two):
                return "changing the repository settings is for the owner"
            if two.startswith("workflow run") and "release" in line:
                return "running the release workflow is for the owner"
            if w[1] == "api" and re.search(r"(-X|--method)\s*(DELETE|PUT|PATCH)", line, re.I):
                return "DELETE/PUT/PATCH through gh api is not allowed"
            continue

        if re.match(r"^(rm|rmdir|Remove-Item|rd|del)$", w[0]):
            for a in w[1:]:
                a2 = a.rstrip("/\\")
                if a2 in ("", "~", "$HOME", "/", "*", "/*") or a2.endswith(".git") or re.match(r"^[A-Za-z]:$", a2) \
                        or a2 in (os.path.expanduser("~"), "/home", "/mnt/c"):
                    return "deleting .git, the root or the home folder is not allowed"
    return None


def log_block(cmd, why, e, cwd):
    try:
        root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
        logdir = os.path.join(root, ".claude", "logs")
        os.makedirs(logdir, exist_ok=True)
        now = datetime.datetime.now().astimezone()
        c = re.sub(r"\s+", " ", cmd).strip()
        c = c[:300] + " ..." if len(c) > 300 else c
        line = "%s  %-16s %-9s %s   -> %s" % (now.strftime("%H:%M:%S"), "[" + (e.get("agent_type") or "main") + "]",
                                             "BLOCKED", c, why)
        with open(os.path.join(logdir, now.strftime("%Y-%m-%d") + ".log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def main():
    try:
        e = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        cmd = str((e.get("tool_input") or {}).get("command") or "")
    except Exception:
        return 0
    if not cmd:
        return 0
    cwd = e.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or "."
    why = check(cmd, cwd)
    if not why:
        return 0
    log_block(cmd, why, e, cwd)
    sys.stderr.write("Blocked by the project guard: %s. Work on an agent/* branch and open a pull "
                     "request; the owner merges and releases.\n" % why)
    return 2


if __name__ == "__main__":
    sys.exit(main())
