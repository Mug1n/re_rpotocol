param(
    [Parameter(Mandatory = $true)]
    [string]$OutputZip
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$zipPath = [IO.Path]::GetFullPath($OutputZip)
$status = @(git -C $repoRoot status --porcelain=v1)
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Git status.' }
if ($status.Count -ne 0) { throw 'Refusing to package a dirty worktree. Commit or restore changes first.' }
if (Test-Path -LiteralPath $zipPath) { throw "Output already exists: $zipPath" }

$stageRoot = Join-Path ([IO.Path]::GetTempPath()) ("re_rpotocol-package-" + [Guid]::NewGuid().ToString('N'))
$projectRoot = Join-Path $stageRoot 're_rpotocol'
New-Item -ItemType Directory -Path $projectRoot | Out-Null
try {
    $tracked = @(git -C $repoRoot ls-files)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw 'No tracked files were found.' }
    $records = @()
    foreach ($relative in $tracked) {
        $source = [IO.Path]::GetFullPath((Join-Path $repoRoot $relative))
        if (-not $source.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Tracked path escapes repository: $relative"
        }
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Tracked file is missing: $relative" }
        $target = Join-Path $projectRoot $relative
        $targetParent = Split-Path -Parent $target
        New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $target
        $item = Get-Item -LiteralPath $source
        $records += [ordered]@{
            path = $relative.Replace('\', '/')
            length = $item.Length
            sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schema_version = '0.1'
        commit = (git -C $repoRoot rev-parse HEAD).Trim()
        created_at_utc = [DateTime]::UtcNow.ToString('o')
        file_count = $records.Count
        files = $records
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $projectRoot 'PACKAGE-MANIFEST.json') -Encoding utf8
    $zipParent = Split-Path -Parent $zipPath
    if ($zipParent) { New-Item -ItemType Directory -Path $zipParent -Force | Out-Null }
    Compress-Archive -LiteralPath $projectRoot -DestinationPath $zipPath -CompressionLevel Optimal
    Get-FileHash -LiteralPath $zipPath -Algorithm SHA256
}
finally {
    if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
}
