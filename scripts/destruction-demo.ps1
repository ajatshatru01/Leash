$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
& "$repoRoot\.venv\Scripts\leash.exe" destruction-demo
