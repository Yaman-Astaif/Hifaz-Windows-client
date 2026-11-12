# Writes one line per Claude Code event to the action log.
#
#   .claude/logs/YYYY-MM-DD.log    easy to read: time, agent, what it did
#   .claude/logs/YYYY-MM-DD.jsonl  the same with more detail, one JSON object per line
#
# Called by the hooks in .claude/settings.json. The agents cannot skip it.
# Works with Windows PowerShell 5.1 and PowerShell 7. Never blocks Claude:
# any problem here is ignored and the script exits 0.

$ErrorActionPreference = 'Stop'
try {
    [Console]::InputEncoding = [Text.Encoding]::UTF8
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $e = $raw | ConvertFrom-Json

    $root = $env:CLAUDE_PROJECT_DIR
    if (-not $root) { $root = $e.cwd }
    if (-not $root) { exit 0 }
    $dir = Join-Path $root '.claude/logs'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

    function Short([object]$s, [int]$n) {
        if ($null -eq $s) { return '' }
        $t = ([string]$s) -replace '\s+', ' '
        $t = $t.Trim()
        if ($t.Length -gt $n) { $t = $t.Substring(0, $n) + ' ...' }
        return $t
    }
    function Rel([object]$p) {
        if (-not $p) { return '' }
        $p = [string]$p
        $r = ($root -replace '\\', '/').TrimEnd('/') + '/'
        $q = $p -replace '\\', '/'
        if ($q.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $q.Substring($r.Length) }
        return $q
    }
    # What one tool call was about, in a few words.
    function Describe($tool, $in) {
        if ($null -eq $in) { return '' }
        switch -Regex ($tool) {
            '^(Bash|PowerShell)$'      { return Short $in.command 400 }
            '^(Read|Edit|Write|MultiEdit|NotebookEdit)$' { return Rel $in.file_path }
            '^(Grep|Glob)$'            { $s = Short $in.pattern 120; if ($in.path) { $s += '  in ' + (Rel $in.path) }; return $s }
            '^(Agent|Task)$'           { return ('{0}: {1}' -f $in.subagent_type, (Short $in.description 200)) }
            '^Skill$'                  { return ('/{0} {1}' -f $in.skill, (Short $in.args 150)) }
            '^WebFetch$'               { return Short $in.url 200 }
            '^WebSearch$'              { return Short $in.query 200 }
            '^(TodoWrite|TaskCreate|TaskUpdate)$' { if ($in.subject) { return Short $in.subject 150 }; if ($in.status) { return 'status ' + $in.status }; return '' }
            default                    { return Short ($in | ConvertTo-Json -Compress -Depth 3) 200 }
        }
    }

    $agent = if ($e.agent_type) { [string]$e.agent_type } else { 'main' }
    $tool = [string]$e.tool_name
    $kind = ''; $text = ''; $ok = $null; $err = $null

    switch ([string]$e.hook_event_name) {
        'SessionStart'       { $kind = 'SESSION'; $text = 'session started (' + [string]$e.source + ')' }
        'UserPromptSubmit'   { $kind = 'ASK';     $text = Short $e.prompt 600 }
        'SubagentStart'      { $kind = 'START';   $text = 'agent ' + [string]$e.agent_type + ' started' }
        'SubagentStop'       { $kind = 'DONE';    $text = 'agent ' + [string]$e.agent_type + ' finished: ' + (Short $e.last_assistant_message 600) }
        'PostToolUse'        { $kind = $tool.ToUpper(); $text = Describe $tool $e.tool_input; $ok = $true }
        'PostToolUseFailure' { $kind = $tool.ToUpper(); $text = Describe $tool $e.tool_input; $ok = $false; $err = Short $e.error 300 }
        'PermissionDenied'   { $kind = 'BLOCKED'; $text = $tool + ': ' + (Describe $tool $e.tool_input) }
        'Stop'               { $kind = 'REPLY';   $text = Short $e.last_assistant_message 600 }
        default              { $kind = [string]$e.hook_event_name; $text = '' }
    }
    if ($ok -eq $false) { $text = $text + '   -> FAILED: ' + $err }

    $now = Get-Date
    $day = $now.ToString('yyyy-MM-dd')
    $line = '{0}  {1,-16} {2,-9} {3}' -f $now.ToString('HH:mm:ss'), ('[' + $agent + ']'), $kind, $text

    $rec = [ordered]@{
        time    = $now.ToString('o')
        session = [string]$e.session_id
        agent   = $agent
        agentId = [string]$e.agent_id
        event   = [string]$e.hook_event_name
        tool    = $tool
        detail  = $text
        ok      = $ok
        error   = $err
        ms      = $e.duration_ms
    }
    $json = $rec | ConvertTo-Json -Compress -Depth 3

    $enc = New-Object Text.UTF8Encoding($false)
    # Several agents can log at the same moment: retry briefly if the file is busy.
    foreach ($pair in @(@("$day.log", $line), @("$day.jsonl", $json))) {
        $path = Join-Path $dir $pair[0]
        for ($i = 0; $i -lt 10; $i++) {
            try { [IO.File]::AppendAllText($path, $pair[1] + "`n", $enc); break }
            catch { Start-Sleep -Milliseconds (20 + 30 * $i) }
        }
    }
} catch { }
exit 0
