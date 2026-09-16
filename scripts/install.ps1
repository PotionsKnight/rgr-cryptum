param([string]$SourceDirectory = (Join-Path $PSScriptRoot '..\build\bin'))

$ErrorActionPreference = 'Stop'

$InstallDirectory = Join-Path $env:LOCALAPPDATA 'cryptum'
$Files = @('cryptum.exe', 'substitution.dll', 'beaufort.dll', 'trithemius.dll')

foreach ($file in $Files) {
    if (-not (Test-Path (Join-Path $SourceDirectory $file))) {
        throw "'$file' not found in '$SourceDirectory', build the project first"
    }
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
foreach ($file in $Files) {
    Copy-Item -Force -Path (Join-Path $SourceDirectory $file) -Destination $InstallDirectory
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ([string]::IsNullOrEmpty($userPath)) {
    [Environment]::SetEnvironmentVariable('Path', $InstallDirectory, 'User')
}
elseif ($userPath.Split(';') -notcontains $InstallDirectory) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDirectory", 'User')
}

Write-Output "cryptum installed in $InstallDirectory"
