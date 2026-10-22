param(
    [string]$Version = '1.5.0',
    [string]$LoaderPath
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$buildDirectory = Join-Path $repositoryRoot 'build'
$distDirectory = Join-Path $repositoryRoot 'dist'
$stagingRoot = Join-Path $buildDirectory 'release-staging'
$plugin = Join-Path $buildDirectory 'Dishonored2HighFPSFix.asi'
$configuration = Join-Path $repositoryRoot 'd2-high-fps-fix.ini'
$readmeTemplate = Join-Path $repositoryRoot 'release-readme.txt'
$projectLicense = Join-Path $repositoryRoot 'LICENSE'
$thirdPartyNotice = Join-Path $repositoryRoot 'THIRD-PARTY-NOTICES.txt'
$expectedLoaderHash = 'FA266E3513D02C08A1B808F28C10538A489EAFFAA4B0707F7CC1066E71B5AFD7'

foreach ($requiredFile in @($plugin, $configuration, $readmeTemplate,
        $projectLicense, $thirdPartyNotice)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required release input is missing: $requiredFile"
    }
}

function Confirm-ChildPath {
    param([string]$Path, [string]$Parent)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullParent = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $fullPath.StartsWith($fullParent,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside $fullParent : $fullPath"
    }
    return $fullPath
}

function Reset-StagingDirectory {
    param([string]$Path)

    $safePath = Confirm-ChildPath -Path $Path -Parent $buildDirectory
    if (Test-Path -LiteralPath $safePath) {
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $safePath | Out-Null
    return $safePath
}

function Write-PayloadHashes {
    param([string]$Directory)

    $lines = Get-ChildItem -LiteralPath $Directory -File |
        Where-Object Name -ne 'SHA256SUMS.txt' |
        Sort-Object Name |
        ForEach-Object {
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            '{0}  {1}' -f $hash.ToLowerInvariant(), $_.Name
        }
    Set-Content -LiteralPath (Join-Path $Directory 'SHA256SUMS.txt') `
        -Value $lines -Encoding Ascii
}

function New-ReleaseArchive {
    param(
        [string]$Name,
        [string]$Stage,
        [bool]$IncludeLoader,
        [string]$ResolvedLoader
    )

    $stagePath = Reset-StagingDirectory -Path $Stage
    Copy-Item -LiteralPath $plugin -Destination $stagePath
    Copy-Item -LiteralPath $configuration -Destination $stagePath
    Copy-Item -LiteralPath $projectLicense `
        -Destination (Join-Path $stagePath 'LICENSE.txt')

    $releaseReadme = (Get-Content -LiteralPath $readmeTemplate -Raw).Replace(
        '@VERSION@', $Version)
    Set-Content -LiteralPath (Join-Path $stagePath 'README.txt') `
        -Value $releaseReadme -Encoding UTF8

    if ($IncludeLoader) {
        Copy-Item -LiteralPath $ResolvedLoader `
            -Destination (Join-Path $stagePath 'dinput8.dll')
        Copy-Item -LiteralPath $thirdPartyNotice `
            -Destination (Join-Path $stagePath 'THIRD-PARTY-NOTICES.txt')
    }

    Write-PayloadHashes -Directory $stagePath

    $archive = Join-Path $distDirectory ($Name + '.zip')
    $archiveHash = $archive + '.sha256'
    if ((Test-Path -LiteralPath $archive) -or
        (Test-Path -LiteralPath $archiveHash)) {
        throw "Release output already exists; refusing to overwrite: $archive"
    }

    Compress-Archive -Path (Join-Path $stagePath '*') -DestinationPath $archive
    $zipHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    $zipHashLine = '{0}  {1}' -f $zipHash.ToLowerInvariant(),
        [System.IO.Path]::GetFileName($archive)
    Set-Content -LiteralPath $archiveHash -Value $zipHashLine -Encoding Ascii
}

New-Item -ItemType Directory -Force -Path $distDirectory | Out-Null

$pluginOnlyName = "Dishonored2-FPSFix-v$Version-plugin-only"
New-ReleaseArchive -Name $pluginOnlyName `
    -Stage (Join-Path $stagingRoot 'plugin-only') `
    -IncludeLoader $false -ResolvedLoader ''

if ($LoaderPath) {
    $resolvedLoader = (Resolve-Path -LiteralPath $LoaderPath).Path
    $actualLoaderHash =
        (Get-FileHash -LiteralPath $resolvedLoader -Algorithm SHA256).Hash
    if ($actualLoaderHash -ne $expectedLoaderHash) {
        throw "Loader hash mismatch: $actualLoaderHash"
    }

    $bundleName =
        "Dishonored2-FPSFix-v$Version-with-Ultimate-ASI-Loader-v9.7.4"
    New-ReleaseArchive -Name $bundleName `
        -Stage (Join-Path $stagingRoot 'with-loader') `
        -IncludeLoader $true -ResolvedLoader $resolvedLoader
}
