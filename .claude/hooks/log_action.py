#!/usr/bin/env python3
"""Write one line per Claude Code event to the action log.

  .claude/logs/YYYY-MM-DD.log    easy to read: time, agent, what it did
  .claude/logs/YYYY-MM-DD.jsonl  the same with more detail, one JSON object per line

Called by the hooks in .claude/settings.json; the agents cannot skip it.
Standard library only. Never blocks Claude: any problem here is ignored.
"""
import datetime
import json
import os
import re
import sys


def short(s, n):
    if s is None:
        return ""
    t = re.sub(r"\s+", " ", str(s)).strip()
    return t[:n] + " ..." if len(t) > n else t


def rel(p, root):
    if not p:
        return ""
    p = str(p).replace("\\", "/")
    r = root.replace("\\", "/").rstrip("/") + "/"
    return p[len(r):] if p.lower().startswith(r.lower()) else p


def describe(tool, inp, root):
    """What one tool call was about, in a few words."""
    if not isinstance(inp, dict):
        return ""
    if tool in ("Bash", "PowerShell"):
        return short(inp.get("command"), 400)
    if tool in ("Read", "Edit", "Write", "MultiEdit", "NotebookEdit"):
        return rel(inp.get("file_path") or inp.get("notebook_path"), root)
    if tool in ("Grep", "Glob"):
        s = short(inp.get("pattern"), 120)
        return s + ("  in " + rel(inp["path"], root) if inp.get("path") else "")
    if tool in ("Agent", "Task"):
        return "%s: %s" % (inp.get("subagent_type", ""), short(inp.get("description"), 200))
    if tool == "Skill":
        return "/%s %s" % (inp.get("skill", ""), short(inp.get("args"), 150))
    if tool == "WebFetch":
        return short(inp.get("url"), 200)
    if tool == "WebSearch":
        return short(inp.get("query"), 200)
    if tool in ("TodoWrite", "TaskCreate", "TaskUpdate"):
        if inp.get("subject"):
            return short(inp["subject"], 150)
        return "status " + inp["status"] if inp.get("status") else ""
    return short(json.dumps(inp, ensure_ascii=False), 200)


def main():
    e = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    root = os.environ.get("CLAUDE_PROJECT_DIR") or e.get("cwd")
    if not root:
        return
    logdir = os.path.join(root, ".claude", "logs")
    os.makedirs(logdir, exist_ok=True)

    agent = e.get("agent_type") or "main"
    tool = e.get("tool_name") or ""
    ev = e.get("hook_event_name") or ""
    ok, err = None, None

    if ev == "SessionStart":
        kind, text = "SESSION", "session started (%s)" % e.get("source", "")
    elif ev == "UserPromptSubmit":
        kind, text = "ASK", short(e.get("prompt"), 600)
    elif ev == "SubagentStart":
        kind, text = "START", "agent %s started" % e.get("agent_type", "")
    elif ev == "SubagentStop":
        kind = "DONE"
        text = "agent %s finished: %s" % (e.get("agent_type", ""), short(e.get("last_assistant_message"), 600))
    elif ev == "PostToolUse":
        kind, text, ok = tool.upper(), describe(tool, e.get("tool_input"), root), True
    elif ev == "PostToolUseFailure":
        kind, text, ok = tool.upper(), describe(tool, e.get("tool_input"), root), False
        err = short(e.get("error"), 300)
        text += "   -> FAILED: " + err
    elif ev == "PermissionDenied":
        kind, text = "BLOCKED", "%s: %s" % (tool, describe(tool, e.get("tool_input"), root))
    elif ev == "Stop":
        kind, text = "REPLY", short(e.get("last_assistant_message"), 600)
    else:
        kind, text = ev, ""

    now = datetime.datetime.now().astimezone()
    day = now.strftime("%Y-%m-%d")
    line = "%s  %-16s %-9s %s" % (now.strftime("%H:%M:%S"), "[" + agent + "]", kind, text)
    rec = {
        "time": now.isoformat(), "session": e.get("session_id", ""), "agent": agent,
        "agentId": e.get("agent_id", ""), "event": ev, "tool": tool, "detail": text,
        "ok": ok, "error": err, "ms": e.get("duration_ms"),
    }
    # Appends of one short line are atomic, so agents logging at once do not mix lines.
    with open(os.path.join(logdir, day + ".log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")
    with open(os.path.join(logdir, day + ".jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
