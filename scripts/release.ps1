# Release script for locke (Python package) -- Windows equivalent of release.sh.
#
# Usage:
#   .\scripts\release.ps1 patch   # 0.1.0 -> 0.1.1
#   .\scripts\release.ps1 minor   # 0.1.0 -> 0.2.0
#   .\scripts\release.ps1 major   # 0.1.0 -> 1.0.0
#
# What it does:
#   1. Bumps the version in python\pyproject.toml
#   2. Commits the bump
#   3. Merges the current branch into main
#   4. Tags main with vX.Y.Z
#   5. Pushes main + tag (CI publishes to PyPI + GitLab registry)
#   6. Switches back to dev
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("patch", "minor", "major")]
    [string]$Bump
)
$ErrorActionPreference = "Stop"

$Pyproject = "python\pyproject.toml"

Push-Location (git -C $PSScriptRoot rev-parse --show-toplevel)
try {
    # Must be on dev branch
    $branch = (git branch --show-current).Trim()
    if ($branch -ne "dev") {
        throw "must be on the dev branch (currently on '$branch')"
    }

    # Working tree must be clean
    if (git status --porcelain) {
        throw "working tree is dirty -- commit or stash changes first"
    }

    # Read current version
    $content = Get-Content $Pyproject -Raw
    if ($content -notmatch 'version = "(\d+)\.(\d+)\.(\d+)"') {
        throw "could not parse version from $Pyproject"
    }
    $major, $minor, $patch = [int]$Matches[1], [int]$Matches[2], [int]$Matches[3]
    $current = "$major.$minor.$patch"

    switch ($Bump) {
        "major" { $major++; $minor = 0; $patch = 0 }
        "minor" { $minor++; $patch = 0 }
        "patch" { $patch++ }
    }
    $newVersion = "$major.$minor.$patch"
    $tag = "v$newVersion"

    Write-Host "Bumping $current -> $newVersion"

    # Bump version in pyproject.toml
    $content = $content -replace "version = `"$current`"", "version = `"$newVersion`""
    Set-Content $Pyproject $content -NoNewline

    git add $Pyproject
    if ($LASTEXITCODE -ne 0) { throw "git add failed" }

    git commit -m "Bump version to $newVersion"
    if ($LASTEXITCODE -ne 0) { throw "git commit failed" }

    # Merge into main and tag
    git checkout main
    if ($LASTEXITCODE -ne 0) { throw "git checkout main failed" }

    git merge dev --no-edit
    if ($LASTEXITCODE -ne 0) { throw "git merge dev failed" }

    git tag -a $tag -m "Release $tag"
    if ($LASTEXITCODE -ne 0) { throw "git tag failed" }

    # Push
    git push origin main $tag
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }

    # Back to dev and fast-forward
    git checkout dev
    if ($LASTEXITCODE -ne 0) { throw "git checkout dev failed" }

    git merge main --ff-only
    if ($LASTEXITCODE -ne 0) { throw "git merge --ff-only failed" }

    Write-Host ""
    Write-Host "Released $tag -- CI will publish to PyPI and GitLab registry."
}
finally {
    Pop-Location
}
