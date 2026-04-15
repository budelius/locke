# Bump locke version, rebuild, commit, tag, and push to GitLab.
# CI publishes the release package when it sees the v* tag.
#
# Usage: .\scripts\bump.ps1 [patch|minor|major] [-NoPush]
param(
    [ValidateSet("patch", "minor", "major")]
    [string]$Part = "patch",

    [switch]$NoPush
)
$ErrorActionPreference = "Stop"

$Pyproject = "python\pyproject.toml"
$DistDir = "dist"

Push-Location (git -C $PSScriptRoot rev-parse --show-toplevel)
try {
    # --- read current version ------------------------------------------------
    $content = Get-Content $Pyproject -Raw
    if ($content -notmatch 'version = "(\d+)\.(\d+)\.(\d+)"') {
        throw "Could not parse version from $Pyproject"
    }
    $major, $minor, $patch = [int]$Matches[1], [int]$Matches[2], [int]$Matches[3]
    $current = "$major.$minor.$patch"

    switch ($Part) {
        "major" { $major++; $minor = 0; $patch = 0 }
        "minor" { $minor++; $patch = 0 }
        "patch" { $patch++ }
    }
    $next = "$major.$minor.$patch"
    $tag  = "v$next"

    # --- update pyproject.toml -----------------------------------------------
    $content = $content -replace "version = `"$current`"", "version = `"$next`""
    Set-Content $Pyproject $content -NoNewline
    Write-Host "Bumped $current -> $next"

    # --- rebuild -------------------------------------------------------------
    $AbsDistDir = Join-Path (Get-Location) $DistDir
    Remove-Item "$AbsDistDir\locke-*.whl", "$AbsDistDir\locke-*.tar.gz" -ErrorAction SilentlyContinue
    uv build --directory python --out-dir $AbsDistDir
    if ($LASTEXITCODE -ne 0) { throw "uv build failed" }

    Write-Host ""
    Get-ChildItem "$AbsDistDir\locke-$next*" | ForEach-Object { Write-Host "Built: $_" }

    # --- commit & tag --------------------------------------------------------
    git add $Pyproject
    git commit -m "Bump locke to $next"
    if ($LASTEXITCODE -ne 0) { throw "git commit failed" }

    git tag -a $tag -m "Release $next"
    if ($LASTEXITCODE -ne 0) { throw "git tag failed" }
    Write-Host "Tagged $tag"

    # --- push ----------------------------------------------------------------
    if ($NoPush) {
        Write-Host ""
        Write-Host "Skipped push. Run manually:"
        Write-Host "  git push && git push origin $tag"
    } else {
        git push
        git push origin $tag
        Write-Host ""
        Write-Host "Pushed $tag -- CI will publish locke $next to the package registry."
    }
}
finally {
    Pop-Location
}
