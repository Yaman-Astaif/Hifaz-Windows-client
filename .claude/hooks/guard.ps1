# Stops shell commands that only the owner may run. Called before every
# Bash / PowerShell command (see .claude/settings.json). Exit 2 = blocked,
# and the reason is shown to the agent so it can choose another way.
#
# Blocked:
#   - any commit or push while on main/master, any push to main/master
#   - force-push, push --all / --mirror / --tags / --delete, pushing a v* tag
#   - git tag (releases are made by the owner)
#   - gh pr merge, gh release, gh repo delete/edit/rename, gh secret,
#     running the release workflow, DELETE/PUT/PATCH calls through gh api
#   - deleting .git, the drive root or the home folder
#
# The permission rules in settings.json say the same; this is the second lock.

$ErrorActionPreference = 'Stop'
try {
    [Console]::InputEncoding = [Text.Encoding]::UTF8
    $e = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $cmd = [string]$e.tool_input.command
} catch { exit 0 }
if (-not $cmd) { exit 0 }

$cwd = [string]$e.cwd
if (-not $cwd) { $cwd = $env:CLAUDE_PROJECT_DIR }

function CurrentBranch {
    try { return (& git -C $cwd rev-parse --abbrev-ref HEAD 2>$null | Out-String).Trim() } catch { return '' }
}

function Block([string]$why) {
    # Note it in the action log too.
    try {
        $root = $env:CLAUDE_PROJECT_DIR; if (-not $root) { $root = $cwd }
        $dir = Join-Path $root '.claude/logs'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $now = Get-Date
        $agent = if ($e.agent_type) { [string]$e.agent_type } else { 'main' }
        $c = ($cmd -replace '\s+', ' ').Trim(); if ($c.Length -gt 300) { $c = $c.Substring(0, 300) + ' ...' }
        $line = '{0}  {1,-16} {2,-9} {3}   -> {4}' -f $now.ToString('HH:mm:ss'), ('[' + $agent + ']'), 'BLOCKED', $c, $why
        [IO.File]::AppendAllText((Join-Path $dir ($now.ToString('yyyy-MM-dd') + '.log')), $line + "`n", (New-Object Text.UTF8Encoding($false)))
    } catch { }
    [Console]::Error.WriteLine("Blocked by the project guard: $why. Work on an agent/* branch and open a pull request; the owner merges and releases.")
    exit 2
}

$protected = '^(main|master)$'
# Look at each command in a chain (a && b ; c | d) on its own.
$parts = $cmd -split '(?:&&|\|\||;|\||\r?\n)'
foreach ($p in $parts) {
    $t = $p.Trim()
    if (-not $t) { continue }
    $words = @($t -split '\s+' | ForEach-Object { $_.Trim('"', "'") } | Where-Object { $_ -ne '' })
    if ($words.Count -eq 0) { continue }
    $line = ($words -join ' ')

    # git ... (allow "git -C dir push", "git -c x=y push")
    if ($words[0] -match '^git(\.exe)?$') {
        $i = 1
        while ($i -lt $words.Count -and $words[$i].StartsWith('-')) {
            if ($words[$i] -in @('-C', '-c')) { $i += 2 } else { $i += 1 }
        }
        if ($i -ge $words.Count) { continue }
        $sub = $words[$i]
        $rest = @(); if ($i + 1 -lt $words.Count) { $rest = $words[($i + 1)..($words.Count - 1)] }

        if ($sub -eq 'tag') { Block 'creating or changing tags is for the owner (tags start releases)' }

        if ($sub -eq 'commit' -and ((CurrentBranch) -match $protected)) {
            Block 'committing directly on main is not allowed'
        }

        if ($sub -eq 'push') {
            foreach ($w in $rest) {
                if ($w -match '^(-f|--force.*|\+.*|--all|--mirror|--tags|--delete|-d|--follow-tags)$') { Block "git push $w is not allowed" }
            }
            $refs = @($rest | Where-Object { -not $_.StartsWith('-') })
            # $refs[0] is the remote; the rest are what to push.
            $targets = @(); if ($refs.Count -gt 1) { $targets = $refs[1..($refs.Count - 1)] }
            foreach ($r in $targets) {
                $dst = ($r -split ':')[-1] -replace '^refs/heads/', ''
                if ($dst -match $protected) { Block 'pushing to main is not allowed' }
                if ($dst -match '^(refs/tags/)?v\d') { Block 'pushing a version tag is not allowed' }
            }
            if ($targets.Count -eq 0 -and ((CurrentBranch) -match $protected)) {
                Block 'pushing while on main is not allowed'
            }
        }
        continue
    }

    if ($words[0] -match '^gh(\.exe)?$' -and $words.Count -ge 2) {
        $two = ($words[1..([Math]::Min(2, $words.Count - 1))] -join ' ')
        if ($two -match '^pr merge')                             { Block 'merging pull requests is for the owner' }
        if ($words[1] -eq 'release')                             { Block 'releases are made by the owner' }
        if ($words[1] -eq 'secret')                              { Block 'secrets are managed by the owner' }
        if ($two -match '^repo (delete|edit|rename|archive)')    { Block 'changing the repository settings is for the owner' }
        if ($two -match '^workflow run' -and $line -match 'release') { Block 'running the release workflow is for the owner' }
        if ($words[1] -eq 'api' -and $line -match '(-X|--method)\s*(DELETE|PUT|PATCH)') { Block 'DELETE/PUT/PATCH through gh api is not allowed' }
        continue
    }

    # Deleting .git, a drive root or the home folder.
    if ($line -match '^(rm|Remove-Item|rmdir|rd|del)\b' -and $line -match '(^|[\s/\\])(\.git|/|~|[A-Za-z]:\\?|\$HOME|\$env:USERPROFILE)([\s/\\]|$)') {
        Block 'deleting .git, a drive root or the home folder is not allowed'
    }
}
exit 0
