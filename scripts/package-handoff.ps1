$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$archivePath = Join-Path $outputDirectory 'qa-adaptant-handoff.zip'
# Только исходники, документация и lockfile. Локальные данные, env, git и зависимости не входят.
$topLevel = Get-ChildItem -LiteralPath $projectRoot -File | Where-Object {
    $_.Extension -eq '.md' -or $_.Name -in @('package.json', 'package-lock.json', '.gitignore')
}
$sourceDirectories = @('docs', 'packages', 'schemas', 'tests', 'workpacks', 'apps', 'adapters', 'scripts') |
    ForEach-Object { Join-Path $projectRoot $_ } | Where-Object { Test-Path -LiteralPath $_ }
$paths = @($topLevel.FullName) + @($sourceDirectories)
foreach ($sourceDirectory in $sourceDirectories) {
    $forbidden = Get-ChildItem -LiteralPath $sourceDirectory -Recurse -Force -File | Where-Object {
        $_.Name -like '.env*' -or $_.FullName -match '[\\/](node_modules|data|\.auth|\.git)[\\/]'
    }
    if ($forbidden) { throw 'В исходных каталогах обнаружены локальные данные; упаковка остановлена.' }
}
Compress-Archive -LiteralPath $paths -DestinationPath $archivePath -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    if ($archive.Entries.FullName -match '(^|/)(node_modules|data|\.auth|\.git|\.env)(/|$)') {
        throw 'Архив содержит запрещённый путь.'
    }
    [pscustomobject]@{ Archive = $archivePath; Entries = $archive.Entries.Count; SHA256 = (Get-FileHash -LiteralPath $archivePath).Hash }
} finally { $archive.Dispose() }
